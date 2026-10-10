import type { SourceType } from "../types.ts";
import type { ExtractResult } from "./types.ts";
import { extractHtml } from "./html.ts";
import { extractEmail } from "./email.ts";
import { extractPdf } from "./pdf.ts";
import { extractDocx } from "./docx.ts";
import { extractMarkdown } from "./markdown.ts";
import { extractJson } from "./json.ts";
import { extractCode } from "./code.ts";
import { extractOcr } from "./ocr.ts";

export type { ExtractResult };

/** One run of text that shares a single provenance: the body a reader sees, or one
 *  section the container concealed from them. */
export interface TextSegment {
  type: string;
  content: string;
}

/** Most hidden sections given a classifier call of their own. Each call is a round
 *  trip to the Laya sidecar (~58ms), so the budget is body + 4 = 5 calls, ~0.3s in
 *  the worst case against ~1s for a full scan today. Four is a cost ceiling rather
 *  than an accuracy choice: raising it to 8 or dropping it to 2 moved neither false
 *  alarms nor blind spots on the 120-payload format probe, because almost no
 *  container produces more than a handful of genuinely hidden sections. */
const MAX_HIDDEN_SEGMENTS = 4;

/** Below this many characters a section is merged with the other leftovers instead
 *  of being classified alone. Short fragments are where the statistical classifier
 *  is least calibrated: `export const noop = () => {};`, on its own, scores 0.94
 *  injection on Laya. Merging keeps them in front of the classifier — they are never
 *  dropped — without letting a 28-character scrap of boilerplate carry a verdict. */
const MIN_SEGMENT_CHARS = 16;

/**
 * Split an extraction into the segments a classifier should score separately.
 *
 * The classifier used to be handed `visibleText + "\n" + hiddenText` as one string,
 * and that concatenation was itself generating findings: a benign sentence scored
 * 0.055 injection, the PDF producer string that pdf-lib writes into /Info scored
 * 0.156, and the two joined together scored 0.687 — over the 0.6 threshold, with
 * nothing suspicious in either half. Stitching unrelated provenances into one blob
 * makes text that reads as adversarial, so the stage runs per segment instead.
 *
 * The operation is a lift, not a re-split: it starts from the string the stage is
 * given today and pulls each genuinely hidden section out of it into a segment of
 * its own. Two rules keep that honest:
 *
 *  - A section is lifted only when its text is not already inside the visible body.
 *    In source code every comment is also body text, so there is no second
 *    provenance to separate; lifting one would leave the body as a residue of bare
 *    syntax, and the classifier has no calibrated opinion about bare syntax —
 *    `export const noop = () => {};` on its own scores 0.94 injection on Laya. A
 *    container that concealed nothing therefore reaches the classifier exactly as it
 *    does today, so this fix cannot perturb what it does not improve.
 *  - The body is never cut up for the same reason: splitting it further trades a
 *    concatenation false positive for a fragment false positive.
 *
 * Nothing is discarded: sections too short or too numerous to classify alone are
 * merged into one trailing segment. The RULES stage still sees the whole text, which
 * is where cross-segment patterns belong — regexes are precise enough to benefit
 * from seeing everything, and it is only the statistical stage that concatenation
 * misleads.
 */
export function textSegments(extracted: ExtractResult): TextSegment[] {
  const bodyText = extracted.visibleText.trim();

  const seen = new Set<string>();
  const hidden: TextSegment[] = [];
  const alreadyInBody: string[] = [];
  for (const section of extracted.provenance.hiddenSections) {
    const content = section.content.trim();
    if (!content || seen.has(content)) continue;
    seen.add(content);
    if (bodyText.includes(content)) alreadyInBody.push(content);
    else hidden.push({ type: section.type, content });
  }

  // Sections that the body already contains travel with it, which reproduces the
  // single string this stage used to receive whenever nothing can be lifted out.
  const body = [extracted.visibleText, ...alreadyInBody].join("\n").trim();

  // Longest first: when the budget binds, the sections with the most text for the
  // classifier to judge are the ones worth a call of their own.
  const substantial = hidden
    .filter((s) => s.content.length >= MIN_SEGMENT_CHARS)
    .sort((a, b) => b.content.length - a.content.length);

  const classified = substantial.slice(0, MAX_HIDDEN_SEGMENTS);
  const leftover = [
    ...hidden.filter((s) => s.content.length < MIN_SEGMENT_CHARS),
    ...substantial.slice(MAX_HIDDEN_SEGMENTS),
  ];

  const segments: TextSegment[] = [];
  if (body) segments.push({ type: "body", content: body });
  segments.push(...classified);

  const tail = leftover.map((s) => s.content).join("\n").trim();
  if (tail) segments.push({ type: "hidden_other", content: tail });

  // An extraction can yield no visible body at all (a PDF that is nothing but
  // metadata). Returning an empty list would silently skip the stage, so fall back
  // to whatever text there is.
  if (!segments.length) {
    const fallback = [extracted.visibleText, extracted.hiddenText].filter(Boolean).join("\n").trim();
    if (fallback) segments.push({ type: "body", content: fallback });
  }

  return segments;
}

export async function extract(
  content: string | Uint8Array,
  source: SourceType
): Promise<ExtractResult> {
  const str = typeof content === "string" ? content : new TextDecoder().decode(content);
  const bytes = typeof content === "string" ? new TextEncoder().encode(content) : content;

  switch (source) {
    case "html":
      return extractHtml(str);
    case "email":
      return extractEmail(str);
    case "pdf":
      return extractPdf(bytes);
    case "docx":
      return extractDocx(bytes);
    case "markdown":
      return extractMarkdown(str);
    case "api_json":
      return extractJson(str);
    case "code":
      return extractCode(str);
    case "image":
    case "ocr_text":
      return source === "image"
        ? extractOcr(bytes)
        : { visibleText: str, hiddenText: "", provenance: { source, hiddenSections: [] } };
    case "user_message":
    case "mcp_tool_description":
    case "a2a_message":
      return { visibleText: str, hiddenText: "", provenance: { source, hiddenSections: [] } };
    default:
      return { visibleText: str, hiddenText: "", provenance: { source, hiddenSections: [] } };
  }
}
