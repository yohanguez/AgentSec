from langgraph.graph import StateGraph, END

# This would be imported from langchain in real code
class DuckDuckGoSearchRun:
    def run(self, query):
        return "search results"

class PythonREPLTool:
    def run(self, code):
        return eval(code)

class FileReadTool:
    def read(self, path):
        with open(path) as f:
            return f.read()


def search_node(state):
    search = DuckDuckGoSearchRun()
    return {"result": search.run(state["query"])}


def code_executor_node(state):
    executor = PythonREPLTool()
    return {"result": executor.run(state["code"])}


def file_reader_node(state):
    reader = FileReadTool()
    return {"result": reader.read(state["path"])}


# Create workflow
workflow = StateGraph(dict)

# Add nodes - these will be detected as agents
workflow.add_node("search", search_node)
workflow.add_node("execute", code_executor_node)
workflow.add_node("read_file", file_reader_node)

# Add edges - these will be detected as workflow connections
workflow.add_edge("search", "execute")
workflow.add_edge("execute", "read_file")
workflow.add_edge("read_file", END)

# Set entry point
workflow.set_entry_point("search")

# Compile
app = workflow.compile()
