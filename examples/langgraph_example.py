from langchain_community.tools import DuckDuckGoSearchRun
from langchain_experimental.tools import PythonREPLTool
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END


def search_agent(state):
    # This agent uses a web search tool - potential SSRF vulnerability
    search = DuckDuckGoSearchRun()
    query = state.get("query", "")
    results = search.run(query)
    return {"search_results": results}


def code_execution_agent(state):
    # This agent can execute arbitrary code - RCE vulnerability
    python_repl = PythonREPLTool()
    code = state.get("code", "")
    result = python_repl.run(code)
    return {"execution_result": result}


def create_workflow():
    # Initialize LLM
    llm = ChatOpenAI(model="gpt-4")

    # Create graph
    workflow = StateGraph(dict)

    # Add nodes
    workflow.add_node("search", search_agent)
    workflow.add_node("execute", code_execution_agent)

    # Add edges
    workflow.add_edge("search", "execute")
    workflow.add_edge("execute", END)

    # Set entry point
    workflow.set_entry_point("search")

    return workflow.compile()


if __name__ == "__main__":
    app = create_workflow()
    result = app.invoke({"query": "Python programming"})
    print(result)
