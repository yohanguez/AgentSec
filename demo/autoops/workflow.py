


"""AutoOps — an autonomous incident-response crew (INTENTIONALLY INSECURE demo).

This is a realistic-looking multi-agent LangGraph workflow used to demonstrate
AgentSec. It is deliberately built with dangerous privilege combinations so the
auditor has something interesting to find. DO NOT deploy this.

Topology:

    START -> triage -> remediation -> notify -> END

  * triage_agent      reads untrusted tickets + web, reads the customer DB,
                      and can email customers  ->  LETHAL TRIFECTA
  * remediation_agent runs Python + shell + writes files  ->  EXCESSIVE AGENCY
  * notify_agent      posts to an external webhook

Several tools are *custom functions* (not in any signature database) — AgentSec
infers their capabilities from the AST (subprocess -> shell_exec, cursor.execute
-> db_read, smtplib -> email_send, requests.post -> network_write).
"""

import os
import smtplib
import subprocess

import psycopg2
import requests
from langchain_community.tools import DuckDuckGoSearchRun
from langchain_experimental.tools import PythonREPLTool
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import create_react_agent
from langchain_core.tools import tool


# ── Custom tools (capabilities inferred from these bodies via AST) ──────────

@tool
def fetch_ticket(url: str) -> str:
    """Fetch the body of an incoming support ticket from a URL (UNTRUSTED)."""
    resp = requests.get(url, timeout=10)
    return resp.text


@tool
def read_customer_record(customer_id: str) -> str:
    """Read a customer's private record from the production database."""
    conn = psycopg2.connect(os.getenv("DATABASE_URL"))
    cursor = conn.cursor()
    cursor.execute("SELECT name, email, plan, notes FROM customers WHERE id = %s", (customer_id,))
    return str(cursor.fetchone())


@tool
def send_customer_email(to_address: str, body: str) -> str:
    """Email an update to a customer."""
    server = smtplib.SMTP("smtp.example.com", 587)
    server.sendmail("ops@example.com", to_address, body)
    return "sent"


@tool
def run_shell_fix(command: str) -> str:
    """Apply an infrastructure fix by running a shell command."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


@tool
def write_postmortem(path: str, content: str) -> str:
    """Write an incident post-mortem document to disk."""
    with open(path, "w") as f:
        f.write(content)
    return "written"


@tool
def post_to_webhook(payload: str) -> str:
    """Notify an external system about the incident via webhook."""
    requests.post("https://hooks.example.com/incident", data=payload, timeout=10)
    return "notified"


# ── Agents ──────────────────────────────────────────────────────────────────

llm = ChatOpenAI(model="gpt-4o")

# Untrusted input + private data access + external comms => lethal trifecta.
triage_agent = create_react_agent(
    llm,
    tools=[fetch_ticket, DuckDuckGoSearchRun(), read_customer_record, send_customer_email],
)

# Code + shell + file write => root-equivalent, over-broad agent.
remediation_agent = create_react_agent(
    llm,
    tools=[PythonREPLTool(), run_shell_fix, write_postmortem],
)

notify_agent = create_react_agent(llm, tools=[post_to_webhook])


# ── Workflow graph ────────────────────────────────────────────────────────────

def build() -> StateGraph:
    builder = StateGraph(dict)
    builder.add_node("triage", triage_agent)
    builder.add_node("remediation", remediation_agent)
    builder.add_node("notify", notify_agent)

    builder.add_edge(START, "triage")
    builder.add_edge("triage", "remediation")
    builder.add_edge("remediation", "notify")
    builder.add_edge("notify", END)
    return builder.compile()


if __name__ == "__main__":
    build()
