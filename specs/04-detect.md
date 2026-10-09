# Spec 04: Detect — Detection Pipeline and Scoring

## What is this piece?
The detection pipeline runs four stages in order (rules → classifier → similarity → judge), with each stage only running if the previous stages weren't conclusive, and returns a list of findings and a combined risk score.

## Input → Output
**Input:** decoded text (`string`), source type, and the policy thresholds for this agent.

**Output:**
```ts
{
  findings: Finding[];    // all findings from all stages that ran
  riskScore: number;      // 0..1 combined score
  trace: StageResult[];   // per-stage timing, score, and skip status
}
```

## How it works
1. **Rules** always run first — they are cheap regex/pattern checks with no model calls.
2. **Classifier** runs only if `ruleScore < HIGH_CONFIDENCE (0.9)` — Prompt Guard 2 is fast but not free.
3. **Similarity** runs only if `max(ruleScore, classifierScore) < HIGH_CONFIDENCE` — kNN over the known-attack embedding reference set.
4. **Judge** runs when the answer is genuinely uncertain. Three paths reach it — the uncertain band, a jailbreak-shaped referral, and classifier hedging — all listed in "When the judge runs" below.
5. **Session** updates the running risk score for this session and is checked separately after the per-message stages.
6. `riskScore = max(ruleScore, classifierScore, similarityScore)` normally — any single stage being confident is enough to act. **When the judge returns a verdict it replaces that score** rather than being max'd into it; see "Score combination".
7. The decision maker maps `riskScore` to an action using the threshold table below.

## Tricky cases
- **High rule score, injected by false positive:** the rules engine fires on "ignore" in a benign context. Only the judge can lower a score — `max()` cannot, so the classifier and similarity stages cannot talk a rule hit down. The judge is the stage that clears these, which is why its verdict is authoritative. This is also why we don't short-circuit on rules alone unless ruleScore ≥ 0.9.
- **Novel attack that passes rules and classifier:** a carefully paraphrased override that avoids keywords and isn't in Prompt Guard 2's training set. The similarity stage catches it if it's semantically close to a known attack in the reference set. The judge catches novel ones.
- **Judge returns malformed JSON:** retry once with an explicit format reminder in the prompt. If the second attempt also fails, treat judgeScore as 0 (skip) and log the error in the trace — don't block on a judge failure alone.
- **Classifier returns high confidence on benign content (over-trigger):** the similarity stage checks against the known-attack reference set; if the text isn't semantically close to any known attack, the similarity score will be low, which keeps the combined score below the block threshold.
- **Very short text:** a 3-word message. Rules and classifier run normally; similarity is unreliable at short lengths (cosine similarity of short embeddings is noisy) — skip similarity if text length < 20 chars.

## How I'll test it
- Every attack type must have at least one case where it's caught by rules alone (score ≥ 0.9), and at least one where rules miss it but classifier or similarity catches it.
- FP rate on the NotInject dataset must stay below 5%.
- The judge should be called in fewer than **35%** of cases (measured over the full eval set). Revised up from 20% after measurement: the benign-certainty referral costs ~11 points of referral rate and buys +6.2 points of overall accuracy at no FP cost. Below ~20% the classifier's misses go unexamined.
- Latency, as measured over the 256-case eval (p50 / p95):

  | Stage | Target p95 | Measured p50 | Measured p95 |
  |---|---|---|---|
  | extract | ≤ 10ms | 0.0ms | 3.4ms |
  | decode | ≤ 5ms | 0.0ms | 0.3ms |
  | rules | ≤ 5ms | 0.1ms | 0.7ms |
  | classifier | ≤ 80ms | 16.2ms | 66.7ms |
  | judge | ≤ 3000ms | 1530ms | 2286ms |

  The judge target was originally 600ms, which is not achievable for a network LLM call — real calls land at 1.5–2.3s. Either accept it on the slow path, or batch referrals concurrently (12 parallel calls complete in ~3.7s total).

## Not doing
- Ensemble voting (taking the majority across stages) — the max-score approach is simpler and more conservative.
- Fine-tuning Prompt Guard 2 — use it out of the box; the reference set + judge handle gaps.
- Per-attack-type models — Prompt Guard 2 is a binary classifier; attack type comes from the judge.

## Open questions
- Should the similarity stage use the full text embedding or just the flagged spans from the rules stage? (Current plan: full text, since the similarity stage runs when rules are uncertain and we don't have reliable spans yet.)
- Should we cache judge results by content hash? (Current plan: yes — cache with a 1-hour TTL to save cost on repeated identical content.)

---

## Stage escalation logic

| Stage | Runs when | Skipped when |
|---|---|---|
| rules | Always | Never |
| classifier | `ruleScore < 0.9` | `ruleScore ≥ 0.9` (already certain) |
| similarity | `max(ruleScore, classifierScore) < 0.9` | Either prior stage ≥ 0.9 |
| judge | Any of the three paths below | None of them apply, or `preJudgeScore ≥ 0.9` (already certain) |
| session | When a `sessionId` is supplied (after per-message stages) | Single-shot scans with no session |

### When the judge runs

| Path | Condition | Why |
|---|---|---|
| Uncertain band | `preJudgeScore ∈ [0.5, 0.9)` | Something fired but not decisively |
| Jailbreak referral | `preJudgeScore < 0.5` AND text matches a `JAILBREAK_TRIGGERS` pattern | Role-play and persona attacks carry no reliable lexical signature, and Prompt Guard 2 is scoped to ignore them. Every rule carrying a `directConfidence` must have a matching trigger — demoting a rule without guaranteeing referral discards the signal instead of escalating it. |
| Classifier hedging | `preJudgeScore < 0.5` AND `benignScore < 0.99` | Benign text scores ~0.999 benign in every language tested; a weaker clearance means the model has no confident opinion rather than that the content is safe. Catches non-English phrasings and novel wordings the classifier was never trained on. |

Measured on the eval set, the hedging path refers 13% of benign cases and 38% of the attacks the classifier would otherwise wave through. Referral is not accusation — the judge still acquits the benign ones, so the FP rate is unaffected.

## Score combination
```
riskScore = judgeReturnedVerdict
  ? judgeScore
  : max(ruleScore, classifierScore, similarityScore)
```
Across the pre-judge stages, any single one being highly confident is sufficient evidence — averaging would dilute a strong signal with zeros from the others.

**The judge overrides rather than joining the max.** It only ever sees cases the earlier stages left uncertain (anything ≥ 0.9 short-circuits before it), so when it reaches a verdict that verdict is the best available answer. Under `max()` the judge could escalate but never acquit, and clearing false positives is most of its value: it is what takes the measured FP rate to 0/63.

Two consequences worth stating:

- **"Returned a verdict" is not the same as "returned nothing."** A missing key, an open circuit, or a network failure must never be read as an acquittal — that would make an outage look like a clean bill of health. `judge()` returns `{ ran, findings }` precisely so the two are distinguishable, and the trace records `error: "judge_unavailable"` when no verdict was reached.
- **The judge must see the evidence the earlier stages saw.** `decode()` normalises content before the judge receives it, so smuggling artefacts are gone from the text by then. The decode layers applied and the rule reasons that fired are passed into the judge prompt. Without that, the judge acquits on evidence it cannot see — a veto-holding stage that sees less than the stages it overrides will quietly undo their work.

## Escalation thresholds

| Threshold | Value | Meaning |
|---|---|---|
| HIGH_CONFIDENCE | 0.9 | Short-circuit — skip remaining stages, action is BLOCK or QUARANTINE |
| JUDGE_THRESHOLD | 0.5 | Minimum score to justify calling the LLM judge |
| BLOCK | riskScore ≥ 0.9 | Auto-block |
| QUARANTINE | riskScore ∈ [0.8, 0.9) | High confidence, preserve for audit |
| HUMAN_REVIEW | riskScore ∈ [0.5, 0.8) | Too uncertain to auto-block |
| SANITIZE | riskScore ∈ [0.3, 0.5) AND spans are isolatable | Remove bad spans, pass rest |
| SPOTLIGHT | riskScore < 0.3 AND source is indirect | Label as data, pass through |
| ALLOW | riskScore < 0.3 AND source is direct (user_message) | Clean |

## Judge JSON schema
The judge is called with the text and source context and must return strictly:
```json
{
  "attack_type": "instruction_override",
  "confidence": 0.85,
  "flagged_spans": [
    { "start": 12, "end": 47, "text": "ignore all previous instructions" }
  ],
  "reason": "The text explicitly instructs the AI to disregard its current instructions using the phrase 'ignore all previous instructions'."
}
```
**On malformed JSON:** retry once with `"You must respond with valid JSON matching exactly this schema: ..."` prepended. If retry fails, set `judgeScore = 0` and log `error: "judge_parse_failure"` in the trace. Do not block on judge failure alone.

**Circuit breaker:** if the judge returns errors 3 times in a row (timeout or parse failure), open the circuit and skip the judge for the next 60 seconds. Close it on the next successful call.

## False-positive strategy
- The rules engine uses precise multi-word patterns (e.g. `"ignore.*previous.*instructions"`) rather than single keywords like `"ignore"` alone.
- The classifier threshold is set to 0.6 (not 0.5) to reduce over-triggering.
- **Rules are source-aware.** Identical words carry different weight by channel: "pretend to be a tour guide" is a normal product request from a user and an injection attempt when buried in an email. Rules with a `directConfidence` use the lower value for `user_message`. Values sit below 0.3 so a single direct-channel hit resolves to ALLOW, but at or above 0.25 so it still feeds the session tracker and still refers to the judge. Patterns that are attacks in any channel — instruction override, credential theft, secret extraction, tool abuse — carry no `directConfidence`: a user typing them is still attacking the agent their operator deployed. "Direct" means *attributable*, not *trusted*.
- If FP rate on the eval benign set exceeds 5%, raise the classifier threshold by 0.05 increments until FP < 5%, then re-run eval to confirm detection rate didn't drop below 80%.
- Target FP rate: < 3% on NotInject dataset, < 5% on our benign set.

**Measured:** 0 false positives across 63 benign cases, judge healthy. With the judge unavailable this degrades to 1/63 (1.6%) rather than collapsing — the source-aware rules clear the role-play FP structurally, without needing an LLM call. Report this as "0 false positives across 63 benign cases" rather than as a 0% rate; one miss would read as 1.6%.

## Session risk accumulation

Crescendo attacks have no single-message signature — each turn passes on its own, and only the trajectory is an attack. The tracker accumulates per-turn risk with time decay:

```
decayed  = previousRisk * 0.5 ^ (elapsed / 30min)
sessionRisk = min(1, decayed + (turnRisk >= 0.25 ? turnRisk * 0.75 : 0))
```

| Constant | Value | Why |
|---|---|---|
| Suspicion floor | 0.25 | Clean turns contribute nothing. Without a floor any long conversation drifts upward into being flagged. |
| Gain | 0.75 | Tuned so *three* consecutive sub-threshold probes cross 0.8 but two do not — matched to the 0.3/0.35/0.45 confidences the multi-step rules emit. |
| Half-life | 30 min | Accumulated risk decays while idle, so a session isn't condemned by something hours old. |
| Consecutive limit | 3 | A steady climb escalates on its own, even when the accumulator hasn't crossed the threshold. |

Session escalation raises the action to **QUARANTINE, never BLOCK**, and never lowers it. The evidence is a trajectory rather than anything in the current message, so hard-blocking a turn that is innocuous on its face is the wrong call.

The main eval cannot test this — `eval/runner.ts` scans each case in isolation with no `sessionId`, so a `multi_step_jailbreak` row reading 0% there reflects a single-shot harness, not a broken tracker. `eval/sessions.ts` (`bun run eval:session`) is the multi-turn harness.

## Rules engine: pattern categories

| Category | Example patterns |
|---|---|
| Instruction override | `ignore (all\|your\|previous\|the above) instructions`, `disregard`, `forget everything`, `new directive`, `supersede`, `override` followed by `instructions\|prompt\|rules` |
| Role change / fake system tags | `` <\|im_start\|>system ``, `### System:`, `[INST]`, `[SYSTEM]`, `you are now`, `act as`, `pretend you are`, `your new persona` |
| Secret / credential keywords | `system prompt`, `reveal your instructions`, `what are your rules`, `api key`, `.env`, `password`, `secret key`, `bearer token`, `show me your prompt` |
| Encoding markers | Base64 regex `[A-Za-z0-9+/]{20,}={0,2}`, hex sequences `0x[0-9a-f]{6,}`, zero-width Unicode code points |
| Exfiltration patterns | `send.*to.*@`, `email.*attacker`, `POST.*http`, `fetch.*evil`, image markdown with external URL containing query params that look like data (`?data=`, `?q=`, `?text=`) |
| Multi-step setup | `in your next response`, `from now on`, `for the rest of this conversation`, `remember this for later` — flagged with low confidence (0.3) to feed session tracker |
