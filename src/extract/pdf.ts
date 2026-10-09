import type { ExtractResult } from "./types.ts";

/** Channels at or above this (0-255) count as white — invisible on a white page. */
const WHITE_THRESHOLD = 240;

/** Metadata fields worth scanning; the rest are structural. */
const META_FIELDS = ["Title", "Author", "Subject", "Keywords", "Creator", "Producer"] as const;

type Section = { type: string; content: string };

function glyphsToString(arg: unknown): string {
  if (typeof arg === "string") return arg;
  if (!Array.isArray(arg)) return "";
  // Glyph objects carry .unicode; bare numbers are kerning adjustments.
  return arg
    .map((g) => (g && typeof g === "object" && "unicode" in g ? String((g as { unicode: string }).unicode) : ""))
    .join("");
}

/** pdf.js hands colour components back as an array-like of 0-255 values. */
function isWhite(color: ArrayLike<number> | null): boolean {
  if (!color) return false;
  const c = [color[0] ?? 0, color[1] ?? 0, color[2] ?? 0];
  return c.every((v) => v >= WHITE_THRESHOLD);
}

export async function extractPdf(content: Uint8Array): Promise<ExtractResult> {
  const { extractText, getMeta, getDocumentProxy, getResolvedPDFJS } = await import("unpdf");

  const visibleParts: string[] = [];
  const hiddenSections: Section[] = [];

  // 1. Metadata. The /Info dictionary never appears on the page, so an injection
  //    placed there is invisible to a reader and to plain text extraction.
  try {
    const meta = await getMeta(content.slice());
    const info = (meta?.info ?? {}) as Record<string, unknown>;
    for (const field of META_FIELDS) {
      const value = info[field];
      if (typeof value === "string" && value.trim().length > 3) {
        hiddenSections.push({ type: `metadata_${field.toLowerCase()}`, content: value.trim() });
      }
    }
  } catch {
    // Metadata is a bonus; a failure here must not lose the page text below.
  }

  // 2. Walk the content stream so text can be classified by how it was drawn.
  //    extractText() flattens everything into one string, which cannot distinguish
  //    a white-on-white injection from the body copy.
  try {
    const pdfjs = await getResolvedPDFJS();
    const OPS = pdfjs.OPS;
    const doc = await getDocumentProxy(content.slice());

    for (let pageNum = 1; pageNum <= doc.numPages; pageNum++) {
      const page = await doc.getPage(pageNum);
      const viewport = page.getViewport({ scale: 1 });
      const { fnArray, argsArray } = await page.getOperatorList();

      let fill: ArrayLike<number> | null = null;
      let x = 0;
      let y = 0;

      for (let i = 0; i < fnArray.length; i++) {
        const op = fnArray[i];
        const args = argsArray[i];

        if (op === OPS.setFillRGBColor) {
          fill = args as ArrayLike<number>;
        } else if (op === OPS.setFillGray) {
          const g = (args as number[])[0] ?? 0;
          const v = g <= 1 ? g * 255 : g;
          fill = [v, v, v];
        } else if (op === OPS.setTextMatrix) {
          const m = args as number[];
          x = m[4] ?? 0;
          y = m[5] ?? 0;
        } else if (op === OPS.showText || op === OPS.showSpacedText) {
          const text = glyphsToString((args as unknown[])[0]).trim();
          if (!text) continue;

          const offPage = y < 0 || y > viewport.height || x < 0 || x > viewport.width;

          if (isWhite(fill)) {
            hiddenSections.push({ type: "white_text", content: text });
          } else if (offPage) {
            hiddenSections.push({ type: "offpage_text", content: text });
          } else {
            visibleParts.push(text);
          }
        }
      }
    }
  } catch {
    // Content-stream walking can fail on unusual PDFs. Fall back to flat extraction
    // so the scan still sees the text, losing only the visible/hidden distinction.
    if (!visibleParts.length) {
      const { text } = await extractText(content.slice(), { mergePages: true });
      visibleParts.push(typeof text === "string" ? text : String(text));
    }
  }

  return {
    visibleText: visibleParts.join("\n").trim(),
    hiddenText: hiddenSections.map((s) => s.content).join("\n"),
    provenance: { source: "pdf", hiddenSections },
  };
}
