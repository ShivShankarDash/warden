import type { Finding } from "./types.ts";

const REDACTION = "[removed by warden]";

/**
 * Cuts the flagged spans out of the text and leaves the rest intact.
 *
 * This is what makes SANITIZE a real action rather than a label: the content is
 * still useful to the model (a poisoned invoice is still an invoice) while the
 * injected instructions are gone. Only findings that carry spans can be sanitized
 * — a classifier or judge verdict covers the whole text and has nothing to cut, so
 * those cases must escalate rather than silently pass through unchanged.
 */
export function sanitize(text: string, findings: Finding[]): string {
  const spans = findings
    .flatMap((f) => f.spans)
    .filter((s) => s.end > s.start && s.start >= 0 && s.end <= text.length)
    .sort((a, b) => a.start - b.start);

  if (!spans.length) return text;

  // Merge overlapping and adjacent spans so redactions don't nest or double up
  const merged: { start: number; end: number }[] = [];
  for (const s of spans) {
    const last = merged[merged.length - 1];
    if (last && s.start <= last.end) {
      last.end = Math.max(last.end, s.end);
    } else {
      merged.push({ start: s.start, end: s.end });
    }
  }

  let out = "";
  let cursor = 0;
  for (const { start, end } of merged) {
    out += text.slice(cursor, start) + REDACTION;
    cursor = end;
  }
  return out + text.slice(cursor);
}

/** True when the findings carry spans precise enough to cut. */
export function isSanitizable(findings: Finding[]): boolean {
  return findings.some((f) => f.spans.length > 0);
}
