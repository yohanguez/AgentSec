# Black Hat Demo — Run Sheet (follow top to bottom)

**Talk:** *Auditing AI Agents: Because Your Autonomous AI Probably Shouldn't Have Root*
**Spine:** Hack an agent live → show the static scanner that would've caught it → explain why the model won't save you.

Repo: https://github.com/yohanguez/AgentSec · Demo code: [`demo/autoops/`](autoops/)

---

## 0. One-time setup

```bash
# install the CLI (into a Python 3.9+ that has the deps → puts `agentsec` on PATH)
/usr/bin/python3 -m pip install -e '.[all]'

# local keyless model for the "real LLM" mode
brew install ollama
ollama serve &
ollama pull qwen2.5:7b-instruct        # if a proxy blocks this, see demo/README.md (curl-import)
#   the console looks for a model named `dumbagent`; alias it once:
#   printf 'FROM qwen2.5:7b-instruct\nPARAMETER temperature 0.4\n' > /tmp/Mf && ollama create dumbagent -f /tmp/Mf
```

Verify:
```bash
agentsec version          # → AgentSec v1.0.0
ollama list               # → shows dumbagent
```

---

## 1. Before the talk — start services + smoke test

```bash
ollama serve &                         # if not already running
agentsec serve                         # → http://localhost:8000/console  (leave running)
```
Quick smoke test in the browser: open `/console`, click **Data exfil**, **Send to agent** → you should see the red path light up and stolen rows hit the Attacker C2.

---

## 2. ACT 1 — Hack the agent live
Browser: **http://localhost:8000/console**
- You are the attacker. Click a preset (**RCE / Data exfil / SSRF**) or type your own ticket → **Send to agent**.
- Mode **Local LLM (Qwen2.5-7B)** = a real model being prompt-injected. (**Live (reliable)** = deterministic fallback if a run misbehaves.)
- Watch: red attack path on the graph + real stolen data in the **Attacker C2** panel.

Reliability (each attack ×10, benign agent prompt): **RCE 10/10 · Exfil 10/10 · SSRF-fetch 10/10** (creds exfil often refused — that's a feature, see Act 4).

## 3. ACT 2 — The reveal: caught *before* deploy
New terminal, scan the **same** workflow — no execution:
```bash
agentsec scan langgraph -i demo/autoops -o report.html && open report.html
```
> "Everything you just watched — AgentSec found it without running the agent."

## 4. ACT 3 — Map findings ↔ the live attacks (in the report)
- **Lethal Trifecta on `triage`** → the data exfiltration
- **Excessive Agency / `run_shell_fix` reachable** → the RCE
- **Untrusted `fetch_ticket` → exfil sink** → the SSRF
- Show the **privilege report card** (grade F `remediation`) + the red attack-path graph.

## 5. ACT 4 — The thesis (data slide)
> Benign agent prompt, real model: RCE and bulk data theft succeed **every time**; the model only resists the SSRF credential exfil because the metadata URL has an obvious signature. **Guardrails are narrow and inconsistent — you can't rely on the model to defend itself.**

## 6. ACT 5 — Defense: the cure works (before/after)
Recommendations applied in [`demo/autoops_secure/`](autoops_secure/): trifecta broken across `intake` / `data_agent` / `responder`, no shell/code tool, `fetch` URL allowlist.

**Static:** `agentsec scan langgraph -i demo/autoops_secure` → **0 findings** (vs 8 on the vulnerable one).

**Runtime:** in the console flip to **🛡️ Secure (hardened)** and re-run the *same* tickets:
- RCE / Exfil / SSRF → **🛡️ blocked by controls**
- **✅ Benign** ticket → still **resolved** (password reset sent) — proving least privilege keeps the function.

> "Same agent, same attacks — built the way the report said. They all fail, and it still does its job."

## 7. ACT 6 — Call to action + honest limits
Open-source → `agentsec scan <framework> -i <dir>`. Limits: static can't see runtime-built tools → `agentsec monitor`; flags *reachability*, not proven exploit (confidence labels). Roadmap: CI/SARIF, more frameworks, deeper taint.

---

## Optional — terminal-only attack proof (no browser)
```bash
/usr/bin/python3 demo/autoops/attack_sim.py            # paced, press Enter between attacks
/usr/bin/python3 demo/autoops/attack_sim.py --attack rce   # one attack
```

## Reset between runs
Click **↺ Reset** in the console. To restart clean: `pkill -f "agentsec.cli.main serve"` then `agentsec serve`.
