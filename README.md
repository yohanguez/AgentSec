# AgentSec

**Static Security Analysis for AI Agent Workflows**

AgentSec is a security scanner that analyzes AI agent workflows built with popular frameworks like LangGraph, CrewAI, OpenAI Agents, Autogen, and n8n. It detects security vulnerabilities, maps them to OWASP/CWE standards, and generates detailed HTML reports with interactive visualizations.

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- Poetry (recommended) or pip

### Install with Poetry (Recommended)

```bash
# Clone the repository
git clone https://github.com/yohanguez/AgentSec.git
cd AgentSec

# Install dependencies
poetry install

# Activate the virtual environment
poetry shell
```

### Install with pip

```bash
# Clone the repository
git clone https://github.com/yohanguez/AgentSec.git
cd AgentSec

# Install dependencies
pip install -e .
```

## 📖 Quick Start

### Scan a workflow

```bash
# Scan a LangGraph workflow
agentsec scan langgraph --input-dir ./examples

# Scan a CrewAI workflow
agentsec scan crewai --input-dir ./my-crewai-project

# Scan with all options
agentsec scan langgraph \
  --input-dir ./my-project \
  --output-file my-report.html \
  --export-graph-json
```

### Supported Frameworks

- **LangGraph** - Detect StateGraph workflows and tool usage
- **CrewAI** - Analyze agents, tasks, and crew configurations
- **OpenAI Agents** - Scan Agent SDK implementations
- **Autogen** - Find ConversableAgent patterns
- **n8n** - Parse workflow JSON files

## 📊 Example Report

AgentSec generates comprehensive HTML security reports. Here's an example from a multi-agent workflow analysis:

---

### 📄 [**➡️ CLICK HERE TO VIEW FULL REPORT EXAMPLE**](https://github.com/yohanguez/AgentSec/blob/main/example-report.html) ⬅️

*Download and open the HTML file to see the complete interactive report*

---

### 📈 Report Statistics

<table>
<tr>
<td align="center" width="33%">
<h3>⚠️ 4</h3>
<b>Vulnerabilities</b>
</td>
<td align="center" width="33%">
<h3>🤖 3</h3>
<b>Agents</b>
</td>
<td align="center" width="33%">
<h3>🔧 2</h3>
<b>Tools</b>
</td>
</tr>
</table>

### 🎨 Workflow Visualization

The report includes an interactive graph showing your complete agent workflow:

![AgentSec Workflow Visualization](workflow-visualization.svg)

**Visual Elements:**
- 🔵 **Blue Rounded Boxes** - AI Agents (Supervisor, Research Agent, Developer Agent)
- 🟡 **Yellow Circles** - Tools (DuckDuckGo Search, Python REPL)
- 🟣 **Purple Hexagons** - MCP Servers (Filesystem, Git, PostgreSQL)
- 🟢 **Green Circles** - Start/End nodes
- **Arrows** - Data flow and agent handoffs
- **(X vuln)** - Vulnerability count on each component

### 🔍 What's Included in the Report

The full report includes:

#### 1. **📊 Workflow Visualization**
Interactive graph showing all agents, tools, MCP servers, and their connections

#### 2. **🤖 Agent Details**
Complete information about each agent:
- **Supervisor** (gpt-4) - Coordinates multiple specialized agents
- **Research Agent** (gpt-4-turbo) - Gathers information from web and databases
- **Developer Agent** (gpt-4-turbo) - Writes code and manages files
- Full system prompts and configurations

#### 3. **🔧 Tool Vulnerability Analysis**

**DuckDuckGoSearchRun** (2 vulnerabilities)
- ⚠️ **Server-Side Request Forgery (SSRF)**
  - OWASP: LLM09 - Improper Output Handling
  - CWE: CWE-918
  - Remediation: Validate URLs, implement domain allowlists, disable redirects

- ⚠️ **Information Disclosure**
  - OWASP: LLM06 - Sensitive Information Disclosure
  - CWE: CWE-200
  - Remediation: Filter search results, redact sensitive patterns

**PythonREPL** (2 vulnerabilities)
- ⚠️ **Remote Code Execution (RCE)**
  - OWASP: LLM07 - Insecure Plugin Design
  - CWE: CWE-94
  - Remediation: Use sandboxes, implement resource limits, validate inputs

- ⚠️ **Sandbox Escape**
  - CWE: CWE-693
  - Remediation: Regular updates, minimize attack surface, monitor behavior

#### 4. **🔌 MCP Server Analysis**
Security assessment of Model Context Protocol servers:
- MCP Filesystem Server
- MCP Git Server
- MCP PostgreSQL Server

#### 5. **🛡️ Detailed Remediation**
Step-by-step guidance for each vulnerability with actionable security controls

### 📋 Report Export Options

✅ **HTML Report** - Beautiful, interactive web page with graphs
✅ **JSON Export** - Machine-readable format for CI/CD integration
✅ **SVG Graphs** - Standalone visualizations

## 🔍 What AgentSec Detects

### Vulnerability Categories

- **SSRF (Server-Side Request Forgery)** - Web search tools, HTTP requests
- **Remote Code Execution** - Python REPL, code interpreters
- **Path Traversal** - File system access, document loaders
- **SQL Injection** - Database query tools
- **Prompt Injection** - Unvalidated LLM inputs
- **Data Leakage** - Sensitive information exposure

### Security Frameworks

All vulnerabilities are mapped to:
- **OWASP Top 10 for LLMs**
- **CWE (Common Weakness Enumeration)**
- **MITRE ATT&CK** (where applicable)

## 📁 Project Structure

```
AgentSec/
├── agentsec/
│   ├── analyzers/      # Framework-specific analyzers
│   ├── models/         # Data models (Graph, Node, Edge)
│   ├── mappers/        # Vulnerability mapping
│   ├── report/         # HTML report generation
│   ├── utils/          # AST parsing and file utilities
│   ├── cli/            # Command-line interface
│   └── data/           # Vulnerability database
├── examples/           # Example vulnerable workflows
├── tests/              # Test suite
└── README.md
```

## 🧪 Running Tests

```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=agentsec

# Run specific test file
poetry run pytest tests/test_models.py
```

## 🛠️ Development

### Run Example Demos

```bash
# Test the core functionality
python test_tool.py

# Generate a multi-agent demo report
python test_multi_agent_demo.py

# See vulnerability detection in action
python vulnerability_detection_demo.py
```

## 📝 Example Usage

### Analyze a LangGraph Workflow

```python
from agentsec.analyzers import LangGraphAnalyzer
from agentsec.mappers import VulnerabilityMapper
from agentsec.report import ReportGenerator

# Analyze the code
analyzer = LangGraphAnalyzer(input_dir="./my-project")
graph = analyzer.analyze()

# Map vulnerabilities
mapper = VulnerabilityMapper()
graph = mapper.map_vulnerabilities(graph)

# Generate report
generator = ReportGenerator()
generator.generate_html(graph, "security-report.html")
```

## 🔒 Security Notes

AgentSec performs **static analysis only** - no code execution required. It:
- Parses Python AST (Abstract Syntax Tree)
- Identifies framework patterns
- Maps tools to vulnerability categories
- Generates actionable security reports

## 📄 License

This project is available for use as-is. See repository for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## 📧 Contact

For questions or feedback, please open an issue on GitHub.

---

Built with ❤️ for securing AI agent workflows
