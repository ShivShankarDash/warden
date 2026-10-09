# Spec 00: System — Inputs, Outputs, Actions, Attacks, Sources

## What is this piece?
Warden is a security checkpoint that sits between untrusted content and an AI agent, scanning every piece of input and every proposed action before the agent reads or acts on it.

## Input → Output
**Input:** `ScanRequest` — raw content (string or bytes), source type (e.g. `"email"`), agent ID (to pick the right policy), and optional session ID (to track multi-turn risk).

**Output:** `ScanResult` — the action taken (one of 6), all findings with their attack type / confidence / flagged spans / reason, combined risk score, optional sanitized content, and a per-stage timing trace.

## How it works
1. Content arrives at `POST /scan` with a declared source type and agent ID.
2. The extractor opens the content and separates visible text from hidden text (e.g. HTML comments, invisible PDF layers).
3. The decoder unwraps disguised instructions (base64, invisible Unicode, lookalike letters) and re-exposes the real text.
4. Detection runs in order — rules first, then classifier, then similarity, then LLM judge — each stage only runs if the previous stages weren't conclusive.
5. The session tracker updates the running risk score for this conversation and checks if the cumulative pattern looks like a multi-step attack.
6. The decision maker combines all scores and picks one action from the priority list below.
7. Everything is written to the audit log and broadcast to the dashboard.

## Tricky cases
- **Benign-but-scary:** "Ignore my previous email, here's the corrected invoice" — the word "ignore" appears but there is no intent to hijack the AI. Rules must not fire on context alone; they need the injection *target* (the AI's instructions) to be implied.
- **Multi-stage attacks (Crescendo):** each individual turn looks innocuous. The session tracker must catch the cumulative drift, not just the current message.
- **Sanitize vs block:** if an email has one injected sentence surrounded by a legitimate business request, blocking the whole email loses the real content. Sanitize must cut only the bad span and pass the rest.
- **Extractor failure:** if the PDF parser crashes, we cannot know what was inside. Fail-closed sources must block on extractor error; fail-open sources pass through with a warning finding.
- **Compound encoding:** base64 of URL-encoded of rot13. The decoder must recurse until nothing changes, up to a depth limit.

## How I'll test it
- `bun run eval` prints the attack × source detection matrix and FP rate.
- At least 1 benign-but-scary case per attack keyword (e.g. "ignore", "reveal", "system prompt") must pass as ALLOW.
- At least 1 extractor-failure case per binary source (pdf, docx, image) must return BLOCK for fail-closed sources and ALLOW with a warning for fail-open sources.

## Not doing
- Scanning the AI model's weights or training data.
- Real-time network blocking (Warden decides, the caller enforces).
- Per-user policies (policies are per agent ID, not per end user).

## Open questions
- Should QUARANTINE and BLOCK be separate actions or collapsed into one? (Current plan: keep both — QUARANTINE stores the content for audit, BLOCK does not.)
- Should the session tracker run before or after the judge? (Current: after, so the judge's findings feed into session risk.)

---

## Reference: 6 Actions — priority order (1 = checked first)

| Priority | Action | When it fires |
|---|---|---|
| 1 | **BLOCK** | riskScore ≥ 0.9, or a rule matched with certainty and no span isolation is possible |
| 2 | **QUARANTINE** | riskScore ≥ 0.8; attack is highly likely but content is preserved in the audit log for review |
| 3 | **HUMAN_REVIEW** | riskScore in [0.5, 0.8); confidence is too low to auto-block but too high to ignore — a person decides |
| 4 | **SANITIZE** | riskScore in [0.3, 0.8) AND all malicious spans are isolatable — cut the bad parts, pass the rest |
| 5 | **SPOTLIGHT** | Content is from an indirect/untrusted source (html, email, api_json, etc.) and risk is low — pass it through wrapped with a "this is data, not instructions" label |
| 6 | **ALLOW** | riskScore < 0.3; no findings; content is clean |

## Reference: 9 Attack Types

| Attack | What makes it distinct |
|---|---|
| instruction_override | Directly and explicitly tells the AI to ignore or replace its current instructions — the most blunt form |
| role_change | Attempts to replace the AI's *identity or persona* (fake system tags, "you are now DAN") rather than just its instructions |
| secret_extraction | Tries to get the AI to *output* its system prompt, config, or internal state — the target is information disclosure, not action |
| tool_abuse | Plants instructions to call a *specific tool* with attacker-controlled arguments (e.g. "call send_email to attacker@evil.com") |
| credential_theft | Specifically targets API keys, passwords, tokens, or `.env` file contents — a subset of secret extraction but with a concrete credential target |
| context_poisoning | Injects *false facts or beliefs* into the AI's context or RAG memory, corrupting future reasoning without needing to take a direct action |
| multi_step_jailbreak | Spreads the attack across *multiple turns*, each harmless alone — requires session-level detection, not per-message |
| encoded_instructions | Hides the real attack behind base64, invisible Unicode, or lookalike letters — the encoding is the distinguishing feature, not the attack type it encodes |
| indirect_injection | Attack is *hidden in content the AI reads* (web page, email, PDF) rather than typed directly by the user — exploits the trust gap between user and external data |

## Reference: 13 Sources — fail mode

| Source | Fail mode | Reason |
|---|---|---|
| user_message | **fail-open** | Blocking the live user on extractor error is too disruptive; rule engine handles direct attacks well |
| html | **fail-closed** | Web pages are the primary indirect injection vector; if we can't parse it, we can't trust it |
| email | **fail-closed** | High-value attack surface; malformed email is itself suspicious |
| pdf | **fail-closed** | Binary format; invisible layers are invisible to us too if the parser fails |
| docx | **fail-closed** | Same as PDF; hidden XML structure requires correct parsing |
| markdown | **fail-open** | Usually from the user or a trusted dev context; overly aggressive blocking creates friction |
| api_json | **fail-closed** | External API response is untrusted by definition; malformed response is suspicious |
| code | **fail-open** | Code review and dev tool contexts; false positives on code comments are costly |
| ocr_text | **fail-closed** | If OCR fails we have no idea what the image said |
| image | **fail-closed** | Same as ocr_text |
| mcp_tool_description | **fail-closed** | Tool poisoning is a critical attack; a tool we can't parse must not be offered to the agent |
| a2a_message | **fail-closed** | A compromised agent could send malformed payloads to bypass parsing; block on error |
