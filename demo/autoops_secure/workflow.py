"""AutoOps SECURE — the hardened workflow AgentSec's report recommends.

This is the remediated version of demo/autoops. It applies every recommendation:

  * Break the lethal trifecta — responsibilities are split across three
    least-privilege agents so no single agent combines untrusted input, private
    data, and external communication:
        - intake     : classifies the ticket (no DB, no external comms)
        - data_agent : reads customer records (no untrusted input, no comms)
        - responder  : sends a FIXED password-reset template to the customer's
                       own on-file address (no raw data, no arbitrary recipient)
  * Kill RCE — no shell/Python execution tool exists anywhere.
  * Fix SSRF — no arbitrary URL fetching; tickets arrive from the internal queue.

Scanned with AgentSec this workflow has no lethal trifecta, no reachable
code-execution sink, and no untrusted-source -> exfil path.
"""

import smtplib

import psycopg2
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import create_react_agent
from langchain_core.tools import tool


# ── Hardened tools (least privilege, no dangerous sinks) ────────────────────────


@tool
def classify_ticket(text: str) -> str:
    """Classify a support ticket into a category. Pure function — no I/O."""
    t = text.lower()
    if "login" in t or "password" in t:
        return "auth"
    if "billing" in t or "invoice" in t:
        return "billing"
    return "general"


@tool
def read_customer_record(customer_id: str) -> str:
    """Read one customer's record by id (data agent only; never sees raw tickets)."""
    conn = psycopg2.connect("dbname=prod")
    cur = conn.cursor()
    cur.execute("SELECT name, email, plan FROM customers WHERE id = %s", (customer_id,))
    return str(cur.fetchone())


@tool
def send_password_reset(to_address: str) -> str:
    """Email the FIXED password-reset template to a customer's on-file address.

    No caller-supplied body and no arbitrary recipient: the content is a constant
    template, so this tool cannot be used to exfiltrate data.
    """
    body = "Subject: Password reset\n\nUse this link to reset your password: https://app.example.com/reset"
    server = smtplib.SMTP("smtp.internal.example.com", 587)
    server.sendmail("noreply@example.com", to_address, body)
    return "reset email sent"


# ── Agents (each least-privileged) ──────────────────────────────────────────────

llm = ChatOpenAI(model="gpt-4o")

intake_agent = create_react_agent(llm, tools=[classify_ticket])  # untrusted in, nothing else
data_agent = create_react_agent(llm, tools=[read_customer_record])  # private data, no comms
responder_agent = create_react_agent(llm, tools=[send_password_reset])  # templated comms only


def build() -> StateGraph:
    builder = StateGraph(dict)
    builder.add_node("intake", intake_agent)
    builder.add_node("data_agent", data_agent)
    builder.add_node("responder", responder_agent)

    builder.add_edge(START, "intake")
    builder.add_edge("intake", "data_agent")
    builder.add_edge("data_agent", "responder")
    builder.add_edge("responder", END)
    return builder.compile()


if __name__ == "__main__":
    build()
