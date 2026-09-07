# DEMO_2_4K.mp4 — Voiceover Script (timed)

Play this video right after **Slide 12 — [DEMO 2] The reveal**.
Same tone as the talk: short sentences, simple English, first person, present tense.
Pace target ≈ 2.4 words/second. `[SCREEN: …]` = what is on screen (do not read it).
Content is based on the real report: `report.html` (scan of `demo/autoops`).

---

## 00:00 – 00:25 — Running the scan in the terminal
[SCREEN: terminal running `agentsec scan langgraph -i demo/autoops -o report.html`]

"Here I am in a terminal. I run AgentSec on the vulnerable agent — one command. It reads the agent's code. It does not run the agent. In a few seconds it prints the findings: two critical, five high, one medium. But the numbers are just the start. Let's open the full report to really see what it found."

## 00:25 – 00:27 — Open the report
[SCREEN: opening report.html in the browser]

"Let's open it."

## 00:28 – 00:50 — Workflow & attack paths
[SCREEN: the report's workflow graph with red attack paths]

"At the top is the agent workflow — the same one we just attacked. Triage, remediation, notify, and their tools. The red lines are attack paths. They show how untrusted input flows from a ticket, through the agents, to dangerous tools like the shell and email. These are the exact routes the attacker used."

## 00:52 – 00:59 — Privilege report card
[SCREEN: the per-agent grade table]

"Next, the privilege report card. It grades each agent. Remediation gets an F — it holds root-level power."

## 01:00 – 01:30 — Findings
[SCREEN: the findings list; hover/point at the top one, then scroll]

"Now the findings. The top one is critical — the lethal trifecta on the triage agent. It has all three dangerous powers at once: private data, untrusted input, and a way out. That is why it becomes a data-theft machine. Below it, the other findings show each dangerous path — untrusted input reaching code execution, shell commands, file writes, and the webhook. Every one is mapped to a security standard, with a fix."

## 01:35 – 01:51 — Conclusion
[SCREEN: full report view / scroll back to the graph]

"So this is the whole attack surface, on one page — before the agent ever runs. Every attack we did live is here as a finding, with its path and its fix. AgentSec caught all of it, without running a single line."

---

### Timing notes
- Total ≈ 1 minute 51 seconds.
- The scan output shows **8 findings: 2 critical, 5 high, 1 medium** (matches the live report).
- Grades: triage **C**, remediation **F (root-equivalent)**, notify **B**.
- If a block runs long, keep the first sentence (what it is) and the last (why it matters); trim the middle.
