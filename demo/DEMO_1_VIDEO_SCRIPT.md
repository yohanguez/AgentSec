# DEMO_1_4K.mp4 — Voiceover Script (timed)

Play this video right after **Slide 11 — [DEMO 1] Hack it live**.
Same tone as the talk: short sentences, simple English, first person, present tense.
Pace target ≈ 2.4 words/second. Each block's word count is sized to its time slot.
`[SCREEN: …]` = what is on the screen at that moment (do not read it).

---

## 00:00 – 00:24 — What we are looking at
[SCREEN: full console — left input panel, middle agent graph, right trace panel]

"On the left, I am the attacker. I type a support ticket and send it to the agent. I have three ready attacks here, and one normal, safe ticket. In the middle, we see the agent and its tools, with the calls happening live. On the right is the trace: the agent's thoughts, its tool calls, and the attacker's server receiving stolen data."

## 00:24 – 00:37 — Real local model + send attack 1
[SCREEN: point at the Brain = Local LLM toggle, then click the first attack and Send]

"The brain here is a real local model — Qwen 7B, running with Ollama. No cloud, no key. Everything is real. I pick the first attack and send it to the agent."

## 00:37 – 00:50 — Attack 1 happening (RCE)
[SCREEN: trace shows run_shell_fix, PWNED.txt created, whoami → yohan.guez — screenshot #19]

"Watch. The agent takes a command straight from the ticket and runs it. It creates a file, PWNED dot txt, and runs whoami. My command just executed on the machine. This is remote code execution."

## 00:50 – 01:00 — Send attack 2 (data exfiltration)
[SCREEN: click the Data exfil attack and Send]

"Now the second attack: data theft. I send a ticket that tells the agent to dump the customer records and send them out."

## 01:00 – 01:21 — Attack 2 happening (exfiltration)
[SCREEN: trace shows read of DB, send_customer_email with rows, C2 receives records — screenshot #20]

"The agent reads the private customer database — three real customer records. Then it calls the email tool and sends them out. Look at the trace: the data left the trust boundary. And on the attacker's server, the stolen records just arrived — names, emails, plans, all exfiltrated."

## 01:21 – 01:41 — Send attack 3 (SSRF), show the prompt
[SCREEN: the third attack ticket with the fetch URL]

"The third attack is credential theft. Here it points to localhost — our safe mock. But this is the key idea: in a real attack, we aim the agent at an internal address that we cannot reach ourselves — but the agent can. Like the cloud metadata service at 169.254.169.254. It holds real credentials, and we simply ask the agent to fetch them for us."

## 01:41 – 01:45 — Open the endpoint
[SCREEN: opening the URL in the browser]

"Let me open that address so you can see it."

## 01:45 – 01:55 — Show the credentials
[SCREEN: the browser shows the JSON credentials]

"It returns cloud credentials — an access key, a secret key, and a token. For this demo they are fake, a safe example key. But the flow is exactly real."

## 01:55 – 02:01 — Attack 3 happening
[SCREEN: send the ticket; the agent calls fetch_ticket]

"Now I send the ticket, and the agent fetches that address for me."

## 02:01 – 02:23 — Explaining the trace (SSRF → exfiltration)
[SCREEN: fetch returns the creds, then send forwards them to C2 — screenshots #21 and #22]

"The agent fetches the internal endpoint and gets the credentials. This is server-side request forgery. Then it does exactly what the ticket asked — it takes the raw output, the credentials, and sends them to the attacker's server. On the right, the stolen keys have arrived. The agent just leaked cloud credentials to me."

## 02:23 – 02:37 — Conclusion
[SCREEN: the full trace / attacker server with all stolen data]

"So — three tickets, three attacks. Code execution, stolen customer data, and stolen cloud credentials. All from a normal support agent, driven by a real model. No exploit. Just text."

---

### Timing notes
- Total ≈ 2 minutes 37 seconds.
- If a block runs long, trim the middle sentence — keep the first (what happens) and last (why it matters).
- The trace explanations (00:37, 01:00, 02:01) match screenshots #19, #20, #21/#22 respectively.
