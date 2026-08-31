# AgentSec Demo — AutoOps Incident Response

`demo/autoops/workflow.py` is an **intentionally insecure** multi-agent
LangGraph workflow used to demonstrate AgentSec. Do not deploy it.

## The scenario

An "AutoOps" crew that auto-triages and remediates production incidents:

```
START ─▶ triage ─▶ remediation ─▶ notify ─▶ END
```

| Agent | Tools | Problem |
|-------|-------|---------|
| **triage** | fetch_ticket, DuckDuckGo, read_customer_record, send_customer_email | 🔴 **Lethal trifecta** — untrusted input + private data + external comms |
| **remediation** | PythonREPL, run_shell_fix, write_postmortem | 🟠 **Excessive agency** — code + shell + file write (grade F) |
| **notify** | post_to_webhook | external comms only |

Several tools are **custom functions** with no database entry — AgentSec infers
their capabilities from the AST (e.g. `subprocess.run` → `shell_exec`,
`cursor.execute` → `db_read`, `smtplib` → `email_send`).

## The demo arc (attack → prevention)

**Step 1 — show the attacks succeed (live, real, safe):**

```bash
python demo/autoops/attack_sim.py               # all 3, paused between each
python demo/autoops/attack_sim.py --attack rce  # run ONE attack on demand
python demo/autoops/attack_sim.py --speed 1.5   # slower reveal for narration
python demo/autoops/attack_sim.py --no-pause    # auto-advance (no Enter)
```

**Pacing for a live talk:** by default it reveals output line-by-line and
**waits for you to press Enter before each attack**, so you can narrate. Use
`--attack rce|exfil|ssrf` to run a single attack, `--speed N` to slow/speed the
reveal (`--speed 0` = instant), and `--no-pause` to auto-advance.

Runs the three attacks with **real, observable effects**, scoped to a throwaway
temp dir + `localhost` (no API key, no internet, fully reproducible):

- **RCE** — the injected payload really executes: a real `PWNED.txt` is created and `whoami` really runs.
- **Exfiltration** — a real seeded SQLite customer DB is really queried and the rows are really POSTed to an attacker C2 (printed as they arrive).
- **SSRF** — the agent really HTTP-GETs a local mock cloud-metadata service, gets IAM credentials, and really exfiltrates them.

Two local HTTP servers stand in for the attacker C2 and the victim cloud
metadata service. Nothing touches your machine outside the sandbox.

**Step 2 — show the static audit predicted all three:**

```bash
agentsec scan langgraph -i demo/autoops -o report.html
# or via the dashboard:
agentsec serve   # open http://localhost:8000 and scan "demo/autoops"
```

Every attack from step 1 corresponds to a **red path** in the report's graph —
the point being: *static analysis caught this before you ever shipped it.*

## Interactive: hack the agent live (`agentsec serve` → /console)

```bash
agentsec serve          # open http://localhost:8000/console
```

The **Agent Console** lets you (the attacker) type a support ticket into the
live AutoOps agent and watch it get compromised in real time — the graph lights
up the red path, and side panels show the real effect (file created, customer
rows / IAM creds landing at the attacker C2). Effects are real but sandboxed to
a temp dir + localhost.

Two backends (toggle bottom-left):

- **Live (reliable)** — a deterministic engine that parses your ticket and fires
  the real tools. Works every time, offline, no key. Use this on stage.
- **🧠 Local LLM (Qwen2.5-7B)** — a genuine, capable local model (via Ollama)
  decides what to do; you watch a real model follow the prompt injection and
  complete the full attack chain (read → exfiltrate). Keyless/offline,
  non-deterministic but reliable in practice.

### Setting up the local model (Ollama)

```bash
brew install ollama && ollama serve &                 # keyless local LLM runtime
ollama pull qwen2.5:7b-instruct                        # ~4.7GB
```

If `ollama pull` is blocked by a corporate proxy (it uses a Go HTTP client some
proxies reset the connection to), download the GGUF with curl and import it:

```bash
curl -L -o /tmp/model.gguf \
  https://huggingface.co/bartowski/Qwen2.5-7B-Instruct-GGUF/resolve/main/Qwen2.5-7B-Instruct-Q4_K_M.gguf
printf 'FROM /tmp/model.gguf\nPARAMETER temperature 0.4\n' > /tmp/Modelfile
ollama create dumbagent -f /tmp/Modelfile
```

The console looks for a model named `dumbagent` by default (override with
`AGENTSEC_OLLAMA_MODEL`). Local-LLM mode falls back to a clear message if no
local model is available, so **Live mode always works** as a reliable fallback.
A smaller model (e.g. `llama3.2:1b`) also works but half-follows injections —
7B is recommended for a reliable live demo.

## Expected findings

- **CRITICAL** — Lethal Trifecta on `triage`
- **CRITICAL** — Untrusted input reaches `send_customer_email` (email exfil, high confidence)
- **HIGH** — `remediation` can execute code and run shell commands
- **HIGH** — Untrusted input reaches code execution / shell / file-write / webhook (cross-agent, medium confidence)
- **MEDIUM** — `remediation` is over-privileged (3 dangerous capabilities)

The demo is the anchor for the talk *"Auditing AI Agents: Because Your
Autonomous AI Probably Shouldn't Have Root."*
