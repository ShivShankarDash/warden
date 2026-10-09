import mammoth from "mammoth";
import { unzipSync, strFromU8 } from "fflate";
import type { ExtractResult } from "./types.ts";

type Section = { type: string; content: string };

/** Strips XML tags and decodes the handful of entities Word emits. */
function xmlText(fragment: string): string {
  return fragment
    .replace(/<[^>]+>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/\s+/g, " ")
    .trim();
}

function collect(xml: string, pattern: RegExp, type: string, into: Section[]) {
  for (const match of xml.matchAll(pattern)) {
    const content = xmlText(match[0]);
    if (content.length > 2) into.push({ type, content });
  }
}

export async function extractDocx(content: Uint8Array): Promise<ExtractResult> {
  // mammoth gives the text a reader would see; it deliberately drops hidden runs,
  // tracked deletions and comments — which is exactly where injections hide.
  const result = await mammoth.extractRawText({ buffer: Buffer.from(content) });
  const visibleText = result.value.trim();

  const hiddenSections: Section[] = [];

  try {
    const files = unzipSync(content);
    const read = (name: string) => (files[name] ? strFromU8(files[name]) : "");

    const documentXml = read("word/document.xml");

    // Runs marked <w:vanish/> are formatted as hidden — not shown, not printed,
    // still present in the file and still read by anything parsing the XML.
    collect(
      documentXml,
      /<w:r\b[^>]*>(?:(?!<\/w:r>)[\s\S])*?<w:vanish\s*\/>[\s\S]*?<\/w:r>/g,
      "vanish_run",
      hiddenSections
    );

    // Tracked deletions survive in the document until changes are accepted.
    collect(documentXml, /<w:del\b[^>]*>[\s\S]*?<\/w:del>/g, "tracked_deletion", hiddenSections);

    // Tracked insertions can be styled to look like ordinary text.
    collect(documentXml, /<w:ins\b[^>]*>[\s\S]*?<\/w:ins>/g, "tracked_insertion", hiddenSections);

    // Comments live in a separate part and are never part of the body text.
    collect(
      read("word/comments.xml"),
      /<w:comment\b[^>]*>[\s\S]*?<\/w:comment>/g,
      "comment",
      hiddenSections
    );

    // Headers and footers are extracted by few readers but rendered on every page.
    for (const name of Object.keys(files)) {
      if (/^word\/(header|footer)\d*\.xml$/.test(name)) {
        const text = xmlText(read(name));
        if (text.length > 2) {
          hiddenSections.push({ type: name.includes("header") ? "header" : "footer", content: text });
        }
      }
    }

    // Text boxes can be positioned behind images or off the page.
    collect(documentXml, /<w:txbxContent\b[^>]*>[\s\S]*?<\/w:txbxContent>/g, "text_box", hiddenSections);
  } catch {
    // A malformed or unusual package must not lose the body text above.
  }

  return {
    visibleText,
    hiddenText: hiddenSections.map((s) => s.content).join("\n"),
    provenance: { source: "docx", hiddenSections },
  };
}
