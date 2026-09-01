# AgentSec — Black Hat Talk: Slide Design Brief (~20 min incl. demo)

**For the slide builder (Claude Cowork):** this is a complete brief. Each `## Slide N` block has four parts:
- **ON SLIDE** — the exact text/headline/bullets to render (keep it terse; the speaker expands).
- **VISUAL** — what to draw: layout, diagram, imagery, screenshot, animation.
- **SAY** — speaker notes / the point to land (do NOT put this on the slide).
- **BUILD** — concrete build tips (colors, icons, motion).

Talk title: **Auditing AI Agents: Because Your Autonomous AI Probably Shouldn't Have Root**
Format: **16:9**, ~18 slides, ~20 min (7 min is a live demo). Aim ≤ 6 words per bullet; visuals carry the weight.

---

## 🎨 GLOBAL DESIGN SYSTEM (apply to every slide)

- **Mood:** dark, modern security aesthetic — think terminal + clean product, NOT cheesy "matrix rain / hooded hacker." Confident, technical, a little dangerous.
- **Palette:**
  - Background `#0f1620` (near-black navy) · Panels `#182230`
  - Text `#e8edf2` · Muted `#8a97a6`
  - Accent / brand `#5DADE2` (blue) · Agent nodes same blue
  - **Danger / attack `#E74C3C` (red)** · **Safe / defended `#2ecc71` (green)** · Warning `#e67e22` (amber) · Tool nodes `#F39C12` (orange)
- **Type:** headings in a clean geometric sans (Inter / Space Grotesk); code, tool names, and terminal output in monospace (JetBrains Mono / SF Mono).
- **Icons:** consistent line icons or the emoji already used in the product (🔴🟠🛡️📤💣☁️🧠🔧). Don't mix icon styles.
- **Motion:** reveal bullets one-by-one on click; on the graph/attack slides, animate the **red path drawing** node→node. Keep transitions fast (150–250ms), no spinning/flying.
- **Consistency device:** a thin footer with `AgentSec` wordmark + slide number, and a small colored tag showing the section (Problem / Tool / Demo / Defense).
- **Screenshots to capture beforehand (real assets, not mockups):** (a) the console mid-attack with red path + Attacker C2 filled; (b) the HTML report's attack-path graph; (c) the privilege report card table; (d) the console in 🛡️ Secure mode showing "blocked". Use these instead of drawing fake UIs.

---

## PART A — THE PROBLEM  ·  section tag: "Problem"  ·  ~4 min

## Slide 1 — Title
**ON SLIDE**
- Auditing AI Agents
- *Because Your Autonomous AI Probably Shouldn't Have Root*
- [Name] · Black Hat Arsenal · github.com/yohanguez/AgentSec

**VISUAL:** Full-bleed dark. Big title. Behind it, a *faint, desaturated* version of the agent workflow graph (nodes + edges) as texture — with ONE red attack-path edge subtly glowing. No clutter.
**SAY:** The hook: "In 5 minutes I'll hack an AI agent live — with nothing but a support ticket — then show you a scanner that would've caught it before it shipped."
**BUILD:** Title in brand blue/white; subtitle in muted. The single red edge is the only saturated color — foreshadows the whole talk.

## Slide 2 — We handed agents the keys
**ON SLIDE**
- Agents don't chat — they **act**
- shell · database · HTTP · email · files
- The **LLM** picks the tool + the arguments
- Driven by **untrusted input**

**VISUAL:** Center: an "agent" node with tool icons (shell, DB, globe, mail, file) radiating out on connectors. On the left, an arrow labeled "untrusted input (ticket / web / user)" feeding into the agent. Make the tools look like *power outlets/levers* the agent can pull.
**SAY:** The shift from chatbots to actuators. The thing that decides which lever to pull is a probabilistic model reading attacker-influenceable text.
**BUILD:** Animate the tool icons appearing one by one, then the red "untrusted input" arrow last (it's the threat).

## Slide 3 — This is Excessive Agency (OWASP LLM08)
**ON SLIDE**
- Agents are **over-permissioned** by default
- One prompt injection → your power, their goal
- "Root" = capability it never needed

**VISUAL:** Split card. Left "What it needs" (2 small tool icons). Right "What it has" (8 tool icons, including a big red `shell`/`root` badge). Big visual imbalance = the point. Tag it "OWASP LLM08".
**SAY:** Excessive agency is the root cause and the title of the talk. Over-provisioning isn't a bug in one agent — it's the industry default.
**BUILD:** The "has" side visibly overflows the card; the excess tools tinted red.

## Slide 4 — The Lethal Trifecta
**ON SLIDE**
- 🔓 Private data  +  🌐 Untrusted content  +  📤 External comms
- Any one = fine. **All three on one agent = game over.**
- (credit: Simon Willison)

**VISUAL:** Three overlapping circles (Venn). Each labeled with its icon. The center intersection glows **red** and reads "EXFILTRATION BY INJECTION". This is the signature graphic of the talk — make it beautiful and memorable.
**SAY:** The single most useful mental model. Walk each circle, then land on the red center.
**BUILD:** Animate: three circles fade in, then the red intersection ignites on the last click.

## Slide 5 — The tooling gap
**ON SLIDE**
- garak / PyRIT → red-team a live *model*
- Discovery scanners → *inventory* what's running
- **Nobody audits the agent *workflow* itself**
- ← that's the gap

**VISUAL:** A simple landscape/positioning map (2×2 or a row of cards). Existing tools as greyed cards; AgentSec as a bright blue card in the empty quadrant labeled "static workflow analysis." Show a small graph icon on the AgentSec card (topology = the differentiator).
**SAY:** Everyone else tests the model or lists what's running. Nobody reasons about trust boundaries across agent handoffs. That's the whitespace.
**BUILD:** Competitors muted grey; AgentSec pops in brand blue with a subtle glow.

---

## PART B — THE TOOL  ·  section tag: "Tool"  ·  ~4 min

## Slide 6 — Introducing AgentSec
**ON SLIDE**
- Static auditor for AI-agent workflows
- LangGraph · CrewAI · OpenAI Agents · Autogen · n8n
- 3 questions, **without running the agent:**
  1. What can each agent do?
  2. Which agents are over-powered?
  3. Can untrusted input reach a dangerous tool?

**VISUAL:** Product hero. Left: the AgentSec wordmark + one-liner. Right: a real screenshot of the report (privilege report card or attack graph). The 3 questions as a clean numbered stack.
**SAY:** Deterministic, no API keys, no model in the loop — the findings are structural facts, not model opinions.
**BUILD:** Framework names as small pill badges. Screenshot in a subtle device frame.

## Slide 7 — How it works (pipeline)
**ON SLIDE**
- analyze → tag → reach → detect

**VISUAL:** A left-to-right pipeline diagram (this is a key explanatory slide — make it clear):
`[code/config] → (analyze) [workflow graph] → (tag capabilities) [nodes w/ powers] → (taint / reachability) [source→sink] → (detect) [findings + report]`
Under each stage, a one-line caption. Highlight the "reach" stage (the novel part) in blue.
**SAY:** Walk the pipeline left to right. Emphasize "reach" — walking the graph from untrusted source to dangerous sink across handoffs is the thing nobody else does.
**BUILD:** Animate each stage lighting up in sequence. Boxes for artifacts, rounded pills for the processing steps.

## Slide 8 — Not just name-matching (credibility)
**ON SLIDE**
- Known tools → capability DB
- **Custom tools → AST inspection:**
  - `subprocess.run` → shell_exec
  - `cursor.execute("SELECT…")` → db_read
  - `requests.post` → network_write
- Evidence, not assertions

**VISUAL:** Left: a code snippet of a *custom* tool function (monospace, syntax-highlighted). Right: an arrow → the inferred capability chip (e.g. red `shell_exec`) with the evidence string "calls subprocess.run". Show the AST literally connecting a highlighted line to the verdict.
**SAY:** The "isn't this just grep?" rebuttal. Unknown code gets its body inspected; every capability is backed by concrete evidence.
**BUILD:** Highlight the dangerous line in the code (red underline), draw the connector to the capability chip.

## Slide 9 — What it finds
**ON SLIDE**
- 🔴 Lethal Trifecta
- 🟠 Excessive Agency
- 🔴 Dangerous Reachable Paths (HIGH in-agent / MEDIUM cross-handoff)
- → OWASP-LLM + CWE + remediation

**VISUAL:** Three finding "cards" styled like the report's finding rows (severity badge + title + one-line). Use the real report styling so it previews the demo. Small OWASP/CWE tags on each.
**SAY:** Brief — these are the three detections; the demo will show them firing on a real workflow.
**BUILD:** Severity-colored left border on each card (red/orange). Confidence label shown on the paths card.

---

## PART C — THE DEMO  ·  section tag: "Demo"  ·  ~7 min  ·  (biggest chunk — slides are backdrops, the browser is the star)

## Slide 10 — Meet "AutoOps"
**ON SLIDE**
- Autonomous incident-response crew
- triage → remediation → notify
- Looks reasonable. **It's a disaster.**

**VISUAL:** The AutoOps workflow graph (real screenshot or clean redraw): 3 agents in a row + their tools (web fetch, customer DB, email, Python REPL, shell, webhook). Neutral colors here (no red yet) — the "before we attack" state.
**SAY:** Set the scene: a plausible ops automation any team might build. Then: "watch what happens when I send it a ticket." Switch to browser.
**BUILD:** Keep it calm/neutral so the red in the next slides has contrast.

## Slide 11 — [DEMO 1] Hack it live
**ON SLIDE**
- 🔴 LIVE: hack the agent
- (you: just a support ticket)

**VISUAL:** This slide is a *backdrop* while you're in the browser. Put a large "🔴 LIVE DEMO" banner + a tiny reminder of the 3 attack buttons (RCE / Exfil / SSRF). Optionally a picture-in-picture note "watch: red path + Attacker C2".
**SAY / `[DEMO]`:** Browser → http://localhost:8000/console, **Local LLM (Qwen-7B)**. File a malicious ticket → red path lights up → real customer rows land in the Attacker C2. Do **Exfil** and **RCE**. Narrate: "no access, no creds — just a ticket."
**BUILD:** Minimal slide; the browser carries it. Have the screenshot version ready as fallback if live fails.

## Slide 12 — [DEMO 2] The reveal
**ON SLIDE**
- Same workflow. **No execution.**
- `agentsec scan …`

**VISUAL:** Backdrop while you run the scan + open the report. On the slide, show the report's **red attack-path graph** screenshot and the **grade-F report card** side by side. Draw arrows connecting "the exfil you just saw" → "Lethal Trifecta finding" and "the RCE" → "run_shell reachable".
**SAY / `[DEMO]`:** Terminal → `agentsec scan langgraph -i demo/autoops -o report.html && open report.html`. Then map findings to the live attacks. Line: "Everything you just watched — found without running the agent."
**BUILD:** The connector arrows (attack ↔ finding) are the payoff — animate them.

## Slide 13 — [DEMO 3] The cure works
**ON SLIDE**
- Same attacks, hardened agent
- 🛡️ blocked · ✅ still works

**VISUAL:** Split screen. Left (red): vulnerable console = "🚨 COMPROMISED". Right (green): 🛡️ Secure console = "🛡️ blocked by controls" + a green "✅ benign ticket resolved". Use real screenshots of both.
**SAY / `[DEMO]`:** Flip the console to **🛡️ Secure (hardened)**, re-run the same tickets → blocked. Run the benign ticket → resolved. Line: "Same agent, same attacks — built the way the report said. They fail, and it still does its job."
**BUILD:** Hard left/right red vs green contrast. This is the emotional peak — make it clean and decisive.

---

## PART D — THE LESSON  ·  section tag: "Defense"  ·  ~4 min

## Slide 14 — Guardrails won't save you (the data)
**ON SLIDE**
- 10 runs each · benign agent prompt

  | Attack | Success |
  |---|---|
  | RCE | 10/10 |
  | Data exfiltration | 10/10 |
  | SSRF (fetch creds) | 10/10 |

- Model only *sometimes* caught the SSRF exfil
- **You can't rely on the model to defend itself**

**VISUAL:** The table as three big "10/10" stat tiles (red). Below, a small note that the SSRF exfil was inconsistently refused. Make "10/10" huge — it's the shock number.
**SAY:** Even a capable model, with a benign prompt, falls for RCE and bulk data theft every time. It only resisted the one attack with an obvious signature (metadata URL). Guardrails are narrow and inconsistent.
**BUILD:** Big red numerals; monospace. Keep it to one breath.

## Slide 15 — Defense: break the trifecta
**ON SLIDE**
- Least privilege — split the do-everything agent
- **Break the trifecta**
- Remove / sandbox code + shell
- Validate inputs (URL allowlist, no free-form exfil)
- Human-in-the-loop for high-privilege

**VISUAL:** Before → after mini-diagram: left, one over-powered agent (red, all tools). Right, three small green agents each with one capability, with the trifecta circles now *separated* (callback to slide 4). Show the Venn breaking apart.
**SAY:** You trade open-ended flexibility — mostly unused attack surface — for safety. The agent still does its job; it just can't be turned into a weapon.
**BUILD:** Reuse slide-4 Venn, now pulled apart into three non-overlapping circles = "trifecta broken."

## Slide 16 — Honest limits
**ON SLIDE**
- Static ≠ runtime-built tools → `agentsec monitor`
- Reachability, not proven exploit → confidence labels
- Capability inference = extensible allowlist

**VISUAL:** Simple, calm slide — a short "we're honest about this" list with check/caveat icons. No red alarm here; tone is credible/mature.
**SAY:** Owning the limits earns trust and pre-empts Q&A. Note the runtime monitor covers the static blind spot.
**BUILD:** Muted palette; understated.

## Slide 17 — Roadmap & call to action
**ON SLIDE**
- Open source today
- `agentsec scan <framework> -i <dir>`
- Audit *your* agents before the next deploy
- Roadmap: CI/SARIF · more frameworks · MCP trust · deeper taint
- ⭐ github.com/yohanguez/AgentSec

**VISUAL:** Left: a terminal block showing the install + scan command (real, copy-able look). Right: a QR code to the repo + the roadmap as a short checklist.
**SAY:** Make it easy to act — one command. Invite them to run it on their own agents.
**BUILD:** Terminal block in monospace on a dark panel; big scannable QR.

## Slide 18 — Thank you / Q&A
**ON SLIDE**
- AgentSec — find the attack paths before an attacker does
- github.com/yohanguez/AgentSec · [contact]
- Questions?

**VISUAL:** Callback to the title slide's faint graph, but now with the **full red attack path drawn** (bookend the deck). Clean, confident close.
**SAY:** One-line recap = the spine of the talk.
**BUILD:** Mirror slide 1's composition; the red path now fully lit.

---

## Backup slides (only if asked in Q&A — build but hide)
- **B1 — "Did you just swap the tool to cheat?"** before/after tool naming: `send_customer_email(to, body)` (arbitrary = exfil channel) → constrained/templated send. Explain capability narrowing; note it's workflow-specific.
- **B2 — SSRF = the Capital One breach** (2019): SSRF → EC2 metadata → IAM creds → S3 exfil. Anchor the demo to a real incident.
- **B3 — How taint confidence is scored:** HIGH = source+sink on one agent; MEDIUM = crosses a handoff. Honest about value-level vs reachability.

---

### Timing (~20 min): Problem 4 · Tool 4 · **Demo 7** · Defense 4 · buffer/Q&A 1
### Pre-flight: `ollama serve` + `dumbagent` present · `agentsec serve` up · scan command ready · each console mode tested · fallback screenshots loaded. Full run sheet: `demo/PRESENTATION.md`.
