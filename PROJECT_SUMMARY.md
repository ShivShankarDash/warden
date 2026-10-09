# Warden — Project Summary

Think of Warden like airport security for an AI assistant. The assistant is the plane, and everything it reads or does has to pass security first. Here are the pieces, from the core outward.

---

## The core: Warden itself

### 1. Extractors: "open every bag."
Content arrives in many forms: email, PDF, web page, Word doc, image. Extractors turn each one into plain text, including the hidden stuff (white text, HTML comments, invisible PDF text, text inside images). If the attacker hid it, the extractor must find it.

### 2. Decoder: "x-ray for disguised items."
Attackers disguise instructions in base64, invisible characters or lookalike letters. The decoder unwraps all of that so the next checks see the real message.

### 3. Detectors: "the security checks."
These run in order, cheapest first:

| Stage | What it does | Speed |
|---|---|---|
| **Rules** | Quick pattern checks like "ignore previous instructions" | Instant |
| **Classifier** | A small AI model (Prompt Guard 2) trained to spot injections | Fast |
| **Similarity** | "Does this look like an attack we've seen before, even if reworded?" Uses embeddings | Medium |
| **Judge** | A big LLM asked "is this an attack, which kind, and which exact sentence?" Only runs when earlier checks aren't sure | Slow / expensive |

### 4. Session tracker: "watching a passenger across visits."
Some attacks are spread over many messages, each harmless alone. This keeps a running risk score per conversation.

### 5. Decision maker: "what do we do with this bag?"
It combines all the scores and picks one action:

| Action | Meaning |
|---|---|
| **Allow** | Let it through |
| **Spotlight** | Let it through, but labeled "this is data, not instructions" |
| **Sanitize** | Cut out only the bad sentences and pass the rest |
| **Quarantine / Block** | Stop it |
| **Human Review** | Not sure — a person decides |

### 6. Output guard: "checking what the passenger does after boarding."
Even if something slipped through, Warden checks what the AI tries to do:

- **Tool-call check:** "You're emailing an address that came from a suspicious web page? Denied."
- **Canary:** A secret word planted in the AI's instructions. If it ever appears in the output, someone tricked the AI into leaking its secrets.
- **Exfil check:** Catches links or images that would secretly send data to an attacker's server.

---

## The API: how other systems talk to Warden

The API is just the set of doors into Warden, which runs as a small web server:

| Route | Purpose |
|---|---|
| `POST /scan` | Check this content before my AI reads it |
| `POST /scan-output` | Check what my AI is about to say |
| `POST /check-tool` | My AI wants to do this action — is it okay? |
| `POST /ingest` | Check this document before I save it into memory |
| `GET /review` | The human review queue |
| `GET /metrics` + `/events` | Numbers and live events for the dashboard |

Any company's AI agent could plug into these doors. That's what makes it a product rather than a script.

---

## Things that prove it works

### 7. Test cases: "fake bags with known contents."
A big list of examples where you already know the answer: ~120 attacks, plus harmless-but-scary messages, plus public datasets. Each case says "this is an attack of type X" or "this is safe."

### 8. Eval runner (the "harness"): "the inspector who grades security."
A script (`bun run eval`) that feeds every test case through Warden and checks its answers against the known ones. It prints a scorecard:

- What % of attacks it caught, per attack type and per source
- How often it wrongly blocked harmless content (false alarms)
- How fast each check was

"Harness" just means the setup that runs the tests automatically. "Eval" is short for evaluation, the scoring itself. You run it every evening to see if you improved.

### 9. Demo agent: "the plane we're protecting."
A small fake email assistant with real abilities (read inbox, open links, send emails). You attack it twice: once without Warden (it leaks data) and once with Warden (blocked). That before-and-after is your strongest demo moment.

### 10. Red-team agent: "hiring someone to sneak through security."
An AI that takes your known attacks and disguises them (rewords, encodes, splits across messages) to find what slips past Warden. Every miss gets added to Warden's memory, so it gets better. This is how you show the system learns.

---

## Things that make it visible

### 11. Audit log: "the CCTV recording."
Every scan is saved to a database with what came in, what each check found, the decision, and how long each step took.

### 12. Dashboard: "the security control room."
A web page showing live scans, the step-by-step trace of any decision, catch rates, an attack heatmap, and the human review queue. Judges see it working.

### 13. Policies: "the rulebook per airline."
A small config file per protected AI, setting which tools it's allowed to use, how strict to be, and what to do when unsure. You change behavior without changing code.

---

## How it all fits together

```
Content arrives
   → Extract (open the bag)
   → Decode (x-ray disguises)
   → Rules → Classifier → Similarity → Judge   (security checks, cheapest first)
   → Session tracker (risk across the conversation)
   → Decide (allow / clean / block / ask human)
   → AI reads it

AI wants to act
   → Output guard (tool check, canary, exfil check)

Everything → Audit log → Dashboard

On the side:
   Test cases + Eval runner  → scorecard (does it work?)
   Demo agent                → before/after proof
   Red-team agent            → finds gaps → Warden learns
```

---

> **If you remember one thing:** Warden is the product, the API is how others use it, the eval is how you prove it, and the dashboard is how you show it.
