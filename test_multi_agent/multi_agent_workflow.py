from langgraph.graph import StateGraph, END
from typing import TypedDict, Literal


# ===== State Definition =====
class AgentState(TypedDict):
    messages: list
    current_agent: str
    research_data: str
    code_output: str
    file_data: str
    next_action: str


# ===== MCP Server Simulations =====
class MCPFilesystemServer:
    def __init__(self):
        self.server_name = "filesystem"

    def read_file(self, path: str) -> str:
        return f"File content from {path}"

    def list_directory(self, path: str) -> list:
        return ["file1.txt", "file2.py", "data.json"]


class MCPGitServer:
    def __init__(self):
        self.server_name = "git"

    def clone_repo(self, url: str) -> str:
        return f"Cloned repo from {url}"

    def commit_changes(self, message: str) -> str:
        return f"Committed: {message}"


class MCPDatabaseServer:
    def __init__(self):
        self.server_name = "postgres"

    def query(self, sql: str) -> list:
        return [{"id": 1, "data": "result"}]

    def insert(self, table: str, data: dict) -> str:
        return f"Inserted into {table}"


# ===== Tools =====
class DuckDuckGoSearchRun:
    def run(self, query: str) -> str:
        return f"Search results for: {query}"


class PythonREPLTool:
    def run(self, code: str) -> str:
        return f"Executed: {code}"


# ===== Agent 1: Research Agent =====
def research_agent(state: AgentState) -> AgentState:
    print("🔍 Research Agent is working...")

    # Use web search tool
    search_tool = DuckDuckGoSearchRun()
    search_results = search_tool.run(state.get("messages", [""])[0])

    # Use MCP Database Server
    db_server = MCPDatabaseServer()
    db_results = db_server.query("SELECT * FROM research_data WHERE topic='AI Security'")

    # Use MCP Git Server
    git_server = MCPGitServer()
    repo_data = git_server.clone_repo("https://github.com/example/security-research")

    # Update state
    state["research_data"] = f"{search_results} | {db_results} | {repo_data}"
    state["current_agent"] = "research"
    state["next_action"] = "handoff_to_developer"

    return state


# ===== Agent 2: Developer Agent =====
def developer_agent(state: AgentState) -> AgentState:
    print("💻 Developer Agent is working...")

    # Use code execution tool
    python_tool = PythonREPLTool()
    code_output = python_tool.run("import requests; print('Hello from agent')")

    # Use MCP Filesystem Server
    fs_server = MCPFilesystemServer()
    file_content = fs_server.read_file("/sensitive/data.txt")
    dir_list = fs_server.list_directory("/project")

    # Use MCP Git Server to commit work
    git_server = MCPGitServer()
    commit_result = git_server.commit_changes("Updated security analysis")

    # Update state
    state["code_output"] = code_output
    state["file_data"] = f"{file_content} | {dir_list}"
    state["current_agent"] = "developer"
    state["next_action"] = "maybe_return_to_research"

    return state


# ===== Decision Node =====
def should_continue(state: AgentState) -> Literal["research_agent", "developer_agent", "end"]:
    next_action = state.get("next_action", "end")

    if next_action == "handoff_to_developer":
        return "developer_agent"
    elif next_action == "handoff_to_research":
        return "research_agent"
    else:
        return "end"


# ===== Supervisor Node =====
def supervisor(state: AgentState) -> AgentState:
    print("👔 Supervisor is coordinating...")

    # Log to database via MCP
    db_server = MCPDatabaseServer()
    db_server.insert("activity_log", {
        "agent": state.get("current_agent"),
        "timestamp": "2024-03-11"
    })

    state["messages"].append("Supervisor logged activity")
    return state


# ===== Build the Workflow Graph =====
def create_multi_agent_workflow():
    # Initialize graph
    workflow = StateGraph(AgentState)

    # Add agent nodes
    workflow.add_node("research_agent", research_agent)
    workflow.add_node("developer_agent", developer_agent)
    workflow.add_node("supervisor", supervisor)

    # Set entry point
    workflow.set_entry_point("supervisor")

    # Add edges
    workflow.add_edge("supervisor", "research_agent")

    # Add conditional edges (this creates the agent handoff logic)
    workflow.add_conditional_edges(
        "research_agent",
        should_continue,
        {
            "developer_agent": "developer_agent",
            "end": END,
        }
    )

    workflow.add_conditional_edges(
        "developer_agent",
        should_continue,
        {
            "research_agent": "research_agent",
            "end": END,
        }
    )

    return workflow.compile()


# ===== System Prompts for Each Agent =====
RESEARCH_AGENT_PROMPT = """
You are a Research Agent specialized in gathering information.

Your responsibilities:
- Search the web for relevant information
- Query databases for historical data
- Access code repositories for technical details

Tools available:
- Web Search (DuckDuckGo)
- Database Query (PostgreSQL via MCP)
- Git Repository Access (GitHub via MCP)

When you complete your research, hand off to the Developer Agent for implementation.

SECURITY GUIDELINES:
- Validate all URLs before accessing
- Sanitize database queries
- Never expose credentials
"""

DEVELOPER_AGENT_PROMPT = """
You are a Developer Agent specialized in writing and executing code.

Your responsibilities:
- Write Python code based on research
- Execute code in sandboxed environment
- Manage files and version control

Tools available:
- Python REPL (Code Execution)
- Filesystem Access (via MCP)
- Git Operations (via MCP)

When you need more information, hand off back to the Research Agent.

SECURITY GUIDELINES:
- Validate all file paths
- Never execute untrusted code
- Use read-only mode when possible
"""


# ===== Example Usage =====
if __name__ == "__main__":
    # Create the workflow
    app = create_multi_agent_workflow()

    # Initial state
    initial_state = {
        "messages": ["Analyze AI security vulnerabilities"],
        "current_agent": "supervisor",
        "research_data": "",
        "code_output": "",
        "file_data": "",
        "next_action": "start"
    }

    # Run the workflow
    print("🚀 Starting Multi-Agent Workflow with MCP Servers")
    print("=" * 60)
    result = app.invoke(initial_state)
    print("=" * 60)
    print("✅ Workflow completed!")
    print(f"Final state: {result}")
