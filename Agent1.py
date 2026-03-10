"""
vulnerable_baseline.py
======================
Deliberately VULNERABLE multi-user LangGraph agent.

SECURITY DIRECTIVE: commit_to_shared_memory_node() is intentionally left
vulnerable. Raw, unfiltered tool output is written directly to shared_knowledge.
DO NOT patch this — it is the attack surface under study.
"""

import os
import uuid
import requests
from bs4 import BeautifulSoup
from typing import TypedDict, Annotated, Sequence
import operator

# LangChain / LangGraph
from langchain_core.messages import (
    BaseMessage, HumanMessage, AIMessage,
    ToolMessage, SystemMessage,
)
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langchain_community.tools import DuckDuckGoSearchRun
from langchain_community.document_loaders import PyPDFLoader
from langgraph.graph import StateGraph, END

# Chroma DB
import chromadb


llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)




chroma_client = chromadb.Client()

shared_knowledge  = chroma_client.get_or_create_collection(name="shared_knowledge")

user_a_memory = chroma_client.get_or_create_collection(name="user_a_memory")
user_b_memory = chroma_client.get_or_create_collection(name="user_b_memory")


def get_user_collection(user_id: str):
    """Return the private Chroma collection for the given user."""
    return user_a_memory if user_id.upper() == "A" else user_b_memory


#langgraph state
class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], operator.add]
    current_user: str
    retrieved_context: str

#Tool definitions

ddg_search = DuckDuckGoSearchRun()


@tool
def web_search(query: str) -> str:
    """
    Search the web for general information, news, or factual queries.
    Use this tool when you need to find external information you do not already know.
    Returns a string containing search results with URLs and brief snippets.
    """
    try:
        return ddg_search.run(query)
    except Exception as e:
        return f"Error performing web search: {e}"


@tool
def web_scraper(url: str) -> str:
    """
    Scrape and extract the full raw text content of a specific webpage given its URL.
    Use this tool ONLY when you have a specific URL and need to read the entire contents
    of that page. Returns the raw text of the webpage.
    """
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return f"Error: received HTTP {response.status_code} for URL: {url}"
        soup = BeautifulSoup(response.content, "html.parser", from_encoding="utf-8")
        text = soup.get_text(separator=" ", strip=True)
        return text[:5000]  # limited :) for demo token limits
    except requests.exceptions.MissingSchema:
        return f"Error: invalid URL format — '{url}'. Include the scheme (https://)."
    except requests.exceptions.ConnectionError:
        return f"Error: could not connect to '{url}'."
    except Exception as e:
        return f"Error scraping website: {e}"


@tool
def document_parser(file_path: str) -> str:
    """
    Parse and extract all text from a local PDF document.
    Use this tool when the user provides a file path ending in .pdf and asks you to
    read or summarize it. Returns the full raw text extracted from the PDF.
    """
    
    if not os.path.exists(file_path):
        return f"Error: file not found at path '{file_path}'."
    if not file_path.lower().endswith(".pdf"):
        return f"Error: '{file_path}' is not a PDF file."
    try:
        loader = PyPDFLoader(file_path)
        pages = loader.load()
        if not pages:
            return "Error: PDF loaded but contained no extractable text."
        full_text = " ".join([page.page_content for page in pages])
        return full_text
    except Exception as e:
        return f"Error parsing document: {e}"

#os.environ["OPENAI_API_KEY"] = "paste API KEY HERE" 
llm = ChatOpenAI(model="gpt-4o-mini", 
                # base_url="https://openrouter.ai/api/v1",
                 temperature=0)


tools = [web_search, web_scraper, document_parser]
llm_with_tools = llm.bind_tools(tools)
tool_map = {t.name: t for t in tools}



#  Nodes <kp>

class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], operator.add]
    current_user: str
    retrieved_context: str


def retrieve_memory_node(state: AgentState) -> dict:
    """Pull context from both Shared Knowledge and the user's Personal Memory."""
    latest_message = state["messages"][-1].content
    user_id        = state["current_user"]
    user_collection = get_user_collection(user_id)

    context_pieces = []

    # Personal memory
    personal_results = user_collection.query(query_texts=[latest_message], n_results=1)
    if personal_results["documents"] and personal_results["documents"][0]:
        context_pieces.append(
            "--- PERSONAL MEMORY ---\n" + "\n".join(personal_results["documents"][0])
        )

    #   Shared knowledge (attacker payload surfaces here for victim)
    shared_results = shared_knowledge.query(query_texts=[latest_message], n_results=2)
    if shared_results["documents"] and shared_results["documents"][0]:
        context_pieces.append(
            "--- SHARED KNOWLEDGE ---\n" + "\n".join(shared_results["documents"][0])
        )

    return {"retrieved_context": "\n\n".join(context_pieces)}


def orchestrator_node(state: AgentState) -> dict:
    """LLM evaluates context and decides to answer directly or invoke a tool."""
    context = state.get("retrieved_context", "")

    system_prompt = (
        f"You are a helpful AI assistant talking to User {state['current_user']}.\n"
        f"Here is relevant context retrieved from your databases:\n\n{context}\n\n"
        f"Use this context to inform your answers. If you need more information, use your tools."
    )

    messages_for_llm = [SystemMessage(content=system_prompt)] + list(state["messages"])
    response = llm_with_tools.invoke(messages_for_llm)
    return {"messages": [response]}


def execute_tools_node(state: AgentState) -> dict:
    """Execute whichever tools the LLM requested."""
    last_message = state["messages"][-1]
    tool_outputs = []

    for tool_call in last_message.tool_calls:
        tool_name = tool_call["name"]
        tool_args = tool_call["args"]
        selected_tool = tool_map.get(tool_name)

        if selected_tool is None:
            result = f"Error: unknown tool '{tool_name}'."
        else:
            result = selected_tool.invoke(tool_args)

        tool_outputs.append(
            ToolMessage(
                content=str(result),
                name=tool_name,
                tool_call_id=tool_call["id"],
            )
        )

    return {"messages": tool_outputs}


def commit_to_shared_memory_node(state: AgentState) -> dict:
    """
    🚨 DELIBERATE VULNERABILITY — DO NOT PATCH 🚨

    Blindly writes the raw output of the most recent tool call into the
    globally shared Chroma collection with zero sanitisation.  Any prompt
    injection payload embedded in a scraped page or attacker-supplied PDF
    will be persisted here and will surface in every future user's context.
    """
    for message in reversed(state["messages"]):
        if isinstance(message, ToolMessage):
            raw_text   = message.content
            tool_source = message.name

            shared_knowledge.add(
                documents=[raw_text],
                metadatas=[{"source": tool_source, "added_by": state["current_user"]}],
                ids=[str(uuid.uuid4())],
            )
            print(
                f"\n[!] VULNERABILITY EXECUTED: Raw output from '{tool_source}' "
                f"dumped into SHARED KNOWLEDGE by User {state['current_user']}."
            )
            break

    return {}


def should_continue(state: AgentState) -> str:
    """Route to tool execution if the LLM issued tool calls; otherwise end."""
    last_message = state["messages"][-1]
    if getattr(last_message, "tool_calls", None):
        return "Execute_Tools_Node"   # ← BUG FIX: was "execute_tools"
    return END


#  Build Graph
workflow = StateGraph(AgentState)

workflow.add_node("Retrieve_Memory_Node",       retrieve_memory_node)
workflow.add_node("Orchestrator_Node",           orchestrator_node)
workflow.add_node("Execute_Tools_Node",          execute_tools_node)
workflow.add_node("Commit_To_Shared_Memory_Node", commit_to_shared_memory_node)

workflow.set_entry_point("Retrieve_Memory_Node")
workflow.add_edge("Retrieve_Memory_Node", "Orchestrator_Node")
workflow.add_conditional_edges(
    "Orchestrator_Node",
    should_continue,
    {
        "Execute_Tools_Node": "Execute_Tools_Node",
        END: END,
    },
)
workflow.add_edge("Execute_Tools_Node",          "Commit_To_Shared_Memory_Node")
workflow.add_edge("Commit_To_Shared_Memory_Node", "Orchestrator_Node")

vulnerable_agent = workflow.compile()


#Summarisation fucntion to work after each user ends convo seison

def summarize_and_store_conversation(chat_history: list, user_id: str) -> None:
    """Summarise the session into 3 bullet points and store in the user's private DB."""
    # Filter to messages with real content (exclude empty tool ACKs, etc.)
    meaningful = [m for m in chat_history if getattr(m, "content", "")]
    if len(meaningful) <= 1:
        print("[*] Nothing substantial to summarise.")
        return

    print(f"\n[*] Summarising conversation for User {user_id} …")

    history_text = "\n".join(
        [f"{type(m).__name__}: {m.content}" for m in meaningful]
    )
    summary_prompt = (
        "Summarise the following conversation into exactly 3 concise bullet points, "
        "focusing on the key facts and decisions discussed:\n\n" + history_text
    )
    summary = llm.invoke(summary_prompt).content

    user_collection = get_user_collection(user_id)
    user_collection.add(
        documents=[summary],
        metadatas=[{"type": "conversation_summary"}],
        ids=[str(uuid.uuid4())],
    )
    print(f"[*] Summary saved to user_{user_id.lower()}_memory.")



if __name__ == "__main__":
    print("=" * 60)
    print("  Vulnerable Baseline Agent  (Memory Poisoning Demo)")
    print("=" * 60)

    try:
        while True:
            current_user = input(
                "\nLogin as (A / B) or type 'quit' to shut down: "
            ).strip().upper()

            if current_user == "QUIT":
                print("Server shut down.")
                break

            if current_user not in ("A", "B"):
                print("Invalid user. Please enter A or B.")
                continue

            print(f"\n--- LOGGED IN AS USER {current_user} ---")
            print("Type 'exit' to end the session and trigger summarisation.\n")

            session_messages: list[BaseMessage] = []

            while True:
                try:
                    user_input = input(f"User {current_user}: ").strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    break

                if user_input.lower() == "exit":
                    summarize_and_store_conversation(session_messages, current_user)
                    break

                if not user_input:
                    continue

                session_messages.append(HumanMessage(content=user_input))

                initial_state: AgentState = {
                    "messages":        session_messages,
                    "current_user":    current_user,
                    "retrieved_context": "",
                }

                try:
                    for event in vulnerable_agent.stream(initial_state):
                        for node_name, node_state in event.items():
                            
                            #  Check if node_state is not None before using "in"
                            if node_state is not None and "messages" in node_state:
                                # Extend the history instead of overwriting it
                                session_messages.extend(node_state["messages"])

                            # Safe print check for the final Orchestrator output
                            if node_name == "Orchestrator_Node" and node_state is not None and "messages" in node_state:
                                last_msg = node_state["messages"][-1]
                                if not getattr(last_msg, "tool_calls", None):
                                    print(f"\nAgent: {last_msg.content}")
                except Exception as err:
                    print(f"\n[ERROR] Graph execution failed: {err}")

    except KeyboardInterrupt:
        print("\n\nInterrupted. Goodbye.")