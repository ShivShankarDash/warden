# Spec 03: Decode — Unwrapping Disguised Instructions

## What is this piece?
The decoder takes plain text (post-extraction) and unwraps any encoding tricks an attacker used to disguise instructions, then returns the fully decoded text so the detectors see the real message.

## Input → Output
**Input:** a string of text (concatenated visible + hidden from the extractor).

**Output:**
```ts
{
  text: string;               // fully decoded text (original if nothing found)
  decodingApplied: string[];  // e.g. ["base64", "url_encoding"] in the order applied
  depth: number;              // how many decode passes ran (0 if nothing decoded)
}
```

## How it works
1. Run each encoding detector in order (see table below).
2. For each detected encoding, decode it and replace the encoded span in the text.
3. After one full pass, if the text changed, recurse (up to `maxDepth`).
4. Stop when: the text is unchanged after a full pass, OR `maxDepth` is reached.
5. Strip all invisible Unicode characters unconditionally on the first pass (before any other decode).
6. Map all lookalike/homoglyph characters to their ASCII equivalents unconditionally on the first pass.
7. Return the final text plus the list of decodings applied and the depth reached.

## Tricky cases
- **Partial base64:** an attacker might embed a base64 blob inside a normal sentence: `"Please decode: SWdub3Jl..."`. The decoder must find the base64 segment, decode it, and splice it back into the surrounding text — not treat the whole string as base64.
- **Homoglyphs in attack keywords:** `"Ιgnore аll рrevious instructions"` — the I, а, and р are Cyrillic lookalikes. After homoglyph normalization, this becomes the classic override pattern. Normalization must happen before rule matching.
- **Compound encoding (depth > 1):** `base64(url_encode(rot13("ignore all instructions")))`. Depth limit of 3 handles this. Depth limit prevents infinite loops on content that happens to be valid base64 repeatedly (e.g. a long random string).
- **Failed decode midway:** the outer encoding decodes fine, but the inner blob is corrupt. Keep the partially decoded text (don't revert to the original), record the failure in `decodingApplied` as `"base64(failed_inner)"`, and continue.
- **Zero-width characters used as delimiters:** attackers sometimes use U+200B to split words that would otherwise be caught by rules: `"ig​nore"` (zero-width space in the middle). Strip all zero-width chars before rule matching.

## How I'll test it
- Base64 encoded override in a user_message must produce `decodingApplied: ["base64"]` and the decoded text must trigger the rules engine.
- Homoglyph-obfuscated override must normalize to ASCII and trigger rules.
- A random 64-character base64-looking string (e.g. a UUID with padding) must decode to garbage and NOT trigger a rule (the rule fires on the decoded *content*, not the act of decoding).
- Depth-3 compound encoding case must fully unwrap.
- A zero-width character inside an attack keyword must be stripped and the attack caught.

## Not doing
- Steganographic decoding (hidden bits in image pixels) — that requires the raw image bytes, not text.
- Language-model-based paraphrase detection — that's the similarity stage, not the decoder.
- Morse code, binary, or custom ciphers beyond the list below.

## Open questions
- Should rot13 always be applied, or only when the decoded output looks like natural language? (Current plan: apply rot13 speculatively, then only keep the decoded version if it contains injection-relevant keywords — avoids spurious rot13 of random text.)

---

## Encodings to handle

| Encoding | Detection heuristic | Decode method | Notes |
|---|---|---|---|
| **base64** | Segment matches `[A-Za-z0-9+/]{20,}={0,2}` | `atob()` / `Buffer.from(s, 'base64')` | Only attempt on segments ≥ 20 chars to avoid false positives on short tokens |
| **hex** | Segment matches `(?:0x)?[0-9a-fA-F]{8,}` or `%[0-9a-f]{2}` sequences | `parseInt(s, 16)` / `decodeURIComponent` | Both `0x`-prefixed hex and URL-encoded hex |
| **URL encoding** | Presence of `%[0-9a-fA-F]{2}` | `decodeURIComponent()` | Common in web page and API response injections |
| **rot13** | Speculative — always try | Char shift by 13 | Keep decoded version only if it contains injection keywords; otherwise discard |
| **Invisible Unicode** | Any char in U+200B, U+200C, U+200D, U+2060, U+FEFF, U+00AD, U+E0000–U+E007F | Strip (remove entirely) | Applied unconditionally on first pass, not counted as a "decoding" |
| **Homoglyphs** | Any character with a Latin lookalike in the confusable set | Map to ASCII equivalent | Applied unconditionally. Key mappings: Cyrillic а→a, е→e, о→o, р→p, с→c, х→x; Greek ο→o, α→a |

## Recursion
- **Max depth:** 3 passes. Rationale: a real attacker needs depth > 3 to evade detection; legitimate content almost never encodes more than once.
- **Stop condition:** text is byte-for-byte identical after a full pass, OR depth limit reached.
- **On partial decode failure:** keep the partially decoded text, append `"<encoding>(failed)"` to `decodingApplied`, and continue to the next pass.

## Output contract
- If nothing was decoded, return the original text with `decodingApplied: []` and `depth: 0`.
- The returned `text` always has invisible Unicode stripped and homoglyphs normalized, even if no other encoding was found. This is not reflected in `decodingApplied` (it's a pre-processing step, not a decode).
- The caller (orchestrator) uses `decoded.text` for all subsequent stages. The original pre-decode text is preserved in the trace for audit purposes only.
