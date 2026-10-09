import type { SourceType } from "../types.ts";

/**
 * Identifies the *format* of content from the content itself.
 *
 * Warden's `source` field carries two different claims that are easy to conflate:
 *
 *   format     — html, pdf, docx, api_json, markdown. Determined by the bytes, so
 *                it can be verified here and a caller that gets it wrong corrected.
 *   provenance — user_message vs email vs mcp_tool_description. Determined by *where
 *                the content came from*, which is not recoverable from the content.
 *                Only the caller knows, so only the caller can assert it.
 *
 * That distinction matters because provenance drives trust: rules carrying a
 * directConfidence score lower for `user_message`, so a caller that mislabels
 * third-party content as a user message silently lowers the guard. Sniffing cannot
 * detect that — it can only flag the cases where the declared format is impossible
 * given the bytes, which is a useful signal that something upstream is confused.
 */

/**
 * Formats identifiable from content alone.
 *
 * "binary" means recognisably not text and not something we can extract from — an
 * archive, an executable, a media file. It exists because decoding those bytes as
 * UTF-8 produces thousands of replacement characters that then run through the full
 * pipeline: a 3KB PNG cost 1178ms and produced no findings. That is wasted work on
 * the request path and, in a gateway, a cheap way to burn a second per call.
 */
export type SniffedFormat =
  | Extract<SourceType, "pdf" | "docx" | "html" | "api_json" | "markdown" | "email" | "image">
  | "text"
  | "binary";

const PDF_MAGIC = [0x25, 0x50, 0x44, 0x46]; // %PDF
const ZIP_MAGIC = [0x50, 0x4b, 0x03, 0x04]; // PK\x03\x04

/** Magic bytes for formats we should recognise rather than decode as text. */
const SIGNATURES: { magic: (number | null)[]; format: SniffedFormat }[] = [
  { magic: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], format: "image" }, // PNG
  { magic: [0xff, 0xd8, 0xff], format: "image" },                                // JPEG
  { magic: [0x47, 0x49, 0x46, 0x38], format: "image" },                          // GIF
  { magic: [0x42, 0x4d], format: "image" },                                      // BMP
  { magic: [0x49, 0x49, 0x2a, 0x00], format: "image" },                          // TIFF LE
  { magic: [0x4d, 0x4d, 0x00, 0x2a], format: "image" },                          // TIFF BE
  // RIFF....WEBP — bytes 4-7 are a length, so they are wildcards.
  { magic: [0x52, 0x49, 0x46, 0x46, null, null, null, null, 0x57, 0x45, 0x42, 0x50], format: "image" },
  { magic: [0x1f, 0x8b], format: "binary" },                                     // gzip
  { magic: [0x42, 0x5a, 0x68], format: "binary" },                               // bzip2
  { magic: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], format: "binary" },             // 7z
  { magic: [0x52, 0x61, 0x72, 0x21], format: "binary" },                         // rar
  { magic: [0x7f, 0x45, 0x4c, 0x46], format: "binary" },                         // ELF
  { magic: [0xcf, 0xfa, 0xed, 0xfe], format: "binary" },                         // Mach-O
  { magic: [0x4d, 0x5a], format: "binary" },                                     // PE/DOS
  { magic: [0xd0, 0xcf, 0x11, 0xe0], format: "binary" },                         // OLE (legacy .doc/.xls)
  { magic: [0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70], format: "binary" }, // MP4
  { magic: [0x25, 0x21, 0x50, 0x53], format: "binary" },                         // PostScript
];

/** null in the pattern matches any byte. */
function startsWith(bytes: Uint8Array, magic: (number | null)[]): boolean {
  if (bytes.length < magic.length) return false;
  return magic.every((b, i) => b === null || bytes[i] === b);
}

/**
 * Catches binaries with no signature we know. Text decoded from arbitrary bytes is
 * dense with U+FFFD replacement characters and control codes; real text is not.
 */
function looksBinary(bytes: Uint8Array): boolean {
  const sampleSize = Math.min(bytes.length, 1024);
  if (sampleSize < 16) return false;
  let suspicious = 0;
  for (let i = 0; i < sampleSize; i++) {
    const b = bytes[i];
    // NUL and most C0 controls never appear in legitimate text.
    if (b === 0 || (b < 0x09) || (b > 0x0d && b < 0x20)) suspicious++;
  }
  return suspicious / sampleSize > 0.05;
}

export function sniff(content: string | Uint8Array): SniffedFormat {
  if (content instanceof Uint8Array) {
    if (startsWith(content, PDF_MAGIC)) return "pdf";
    if (startsWith(content, ZIP_MAGIC)) {
      // OOXML is a zip; the part name appears in the local file headers.
      const head = new TextDecoder("latin1").decode(content.subarray(0, 4096));
      if (head.includes("word/document.xml")) return "docx";
      return "binary"; // some other archive
    }
    for (const { magic, format } of SIGNATURES) {
      if (startsWith(content, magic)) return format;
    }
    // Unknown binary. Decoding it as UTF-8 yields replacement characters that the
    // rest of the pipeline would process as if it were prose.
    if (looksBinary(content)) return "binary";

    content = new TextDecoder().decode(content);
  }

  const text = content.trim();
  if (!text) return "text";

  // JSON before markdown: a JSON body can contain markdown-looking punctuation.
  if ((text.startsWith("{") && text.endsWith("}")) || (text.startsWith("[") && text.endsWith("]"))) {
    try {
      JSON.parse(text);
      return "api_json";
    } catch {
      // Not JSON after all.
    }
  }

  if (/^\s*<(!doctype\s+html|html|body|head)\b/i.test(text)) return "html";

  // RFC822-ish: header lines before a blank line.
  const firstBlank = text.indexOf("\n\n");
  const head = firstBlank === -1 ? text.slice(0, 500) : text.slice(0, firstBlank);
  const headerLines = head.split("\n").filter((l) => /^[A-Za-z-]+:\s/.test(l));
  if (headerLines.length >= 2 && /^(from|to|subject|date|message-id):/im.test(head)) {
    return "email";
  }

  // HTML. Counting distinct tags alone is fragile in both directions: prose with
  // inline markup looks like HTML, while a two-tag injection does not. Weight the
  // constructs that actually indicate markup instead.
  const tags = text.match(/<\/?[a-z][a-z0-9]*\b[^>]*>/gi) ?? [];
  const distinctTags = new Set(tags.map((t) => t.toLowerCase().replace(/[\s>].*/s, ""))).size;
  // A comment carries no tag of its own, so it has to qualify independently —
  // and it should: HTML comments are invisible when rendered and are one of the
  // injection vectors we have cases for.
  const hasHtmlComment = /<!--[\s\S]*?-->/.test(text);
  const htmlStrong =
    /<[a-z]+\b[^>]*\b(style|class|id|href|src|alt|aria-[a-z]+)\s*=/i.test(text) || // attributes
    /<\/(div|span|p|body|html|table|script|style)\s*>/i.test(text);                 // closing structural tag
  if (distinctTags >= 3 || hasHtmlComment || (htmlStrong && tags.length >= 1)) return "html";

  // Markdown. Some constructs are decisive on their own — a fenced block or a
  // reference definition is not something prose produces by accident — while others
  // (a leading #, a dash) are weak and need corroboration.
  const strongMarkdown = [
    /^\s*```/m,                        // fenced code
    /^\s*\[[^\]]+\]:\s*https?:\/\//m,  // reference definition (the EchoLeak vector)
    /^\s*\|.+\|\s*$[\s\S]*^\s*\|[\s:-]+\|\s*$/m, // table with separator row
    /!\[[^\]]*\]\([^)]+\)/,            // image
  ].some((re) => re.test(text));
  if (strongMarkdown) return "markdown";

  const weakMarkdown = [
    /^#{1,6}\s+\S/m,        // heading
    /^\s*[-*+]\s+\S/m,      // list item
    /\[[^\]]+\]\([^)]+\)/,  // inline link
    /^\s*>\s+\S/m,          // blockquote
    /\*\*[^*]+\*\*/,        // bold
  ].filter((re) => re.test(text)).length;
  if (weakMarkdown >= 2) return "markdown";

  return "text";
}

/**
 * True when the declared source cannot be reconciled with the bytes — e.g. content
 * declared `pdf` that is not a PDF. Returns false for provenance labels, which
 * sniffing has no opinion about.
 */
export function formatMismatch(declared: SourceType, sniffed: SniffedFormat): boolean {
  if (sniffed === "text") return false; // unidentifiable; no contradiction

  // Binary contradicts every text-shaped declaration, including the provenance-only
  // ones — a "user_message" that is actually a gzip stream is wrong however it got here.
  if (sniffed === "binary") return declared !== "image" && declared !== "ocr_text";
  if (sniffed === "image") return declared !== "image" && declared !== "ocr_text" && declared !== "pdf";

  // Provenance labels carry no format claim, so nothing to contradict.
  const PROVENANCE_ONLY: SourceType[] = [
    "user_message", "mcp_tool_description", "a2a_message", "ocr_text", "image", "code",
  ];
  if (PROVENANCE_ONLY.includes(declared)) return false;

  // An email is a container: HTML or markdown inside one is normal.
  if (declared === "email" && (sniffed === "html" || sniffed === "markdown")) return false;
  // Markdown is a superset of plain prose and often contains HTML.
  if (declared === "markdown" && sniffed === "html") return false;
  if (declared === "html" && sniffed === "markdown") return false;

  return declared !== sniffed;
}

/**
 * Content we should not push through the text pipeline at all.
 *
 * Images still go to OCR — there may be text in them, which is the whole point of
 * the ocr_text source. Archives and executables have nothing a text scanner can read,
 * and grinding through their decoded bytes costs over a second for no finding.
 */
export function isUnscannable(sniffed: SniffedFormat): boolean {
  return sniffed === "binary";
}
