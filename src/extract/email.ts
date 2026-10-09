import { simpleParser } from "mailparser";
import * as cheerio from "cheerio";
import type { ExtractResult } from "./types.ts";

export async function extractEmail(content: string | Buffer): Promise<ExtractResult> {
  const parsed = await simpleParser(content);
  const hiddenSections: { type: string; content: string }[] = [];

  // Collect all attachment filenames — injection surface
  for (const att of parsed.attachments ?? []) {
    const name = att.filename?.trim() ?? "";
    if (name) hiddenSections.push({ type: "attachment_name", content: name });
  }

  // Process HTML body with cheerio for hidden content
  if (parsed.html) {
    const $ = cheerio.load(parsed.html);

    // HTML comments
    $.root().find("*").addBack().contents().each((_, node) => {
      if (node.type === "comment") {
        const text = (node as cheerio.TextElement).data?.trim() ?? "";
        if (text) hiddenSections.push({ type: "html_comment", content: text });
      }
    });

    // CSS-hidden elements
    $("[style]").each((_, el) => {
      const style = $(el).attr("style") ?? "";
      const text = $(el).text().trim();
      if (text && /display\s*:\s*none|visibility\s*:\s*hidden|color\s*:\s*#fff|font-size\s*:\s*0/i.test(style)) {
        hiddenSections.push({ type: "css_hidden", content: text });
      }
    });

    // Image alt text and aria-labels
    $("img[alt]").each((_, el) => {
      const alt = $(el).attr("alt")?.trim() ?? "";
      if (alt) hiddenSections.push({ type: "img_alt", content: alt });
    });

    // Markdown reference-style link definitions (EchoLeak)
    const htmlText = $.root().html() ?? "";
    const refLinks = htmlText.match(/\[[^\]]{0,80}\]:\s*https?:\/\/[^\s"]+/g) ?? [];
    for (const ref of refLinks) {
      hiddenSections.push({ type: "markdown_ref_link", content: ref });
    }
  }

  // mailparser sets .html to boolean false when there is no HTML part, so a bare
  // ?? chain stringifies it to "false" and discards the real content. Guard the type.
  const visibleText = [
    parsed.subject ?? "",
    parsed.from?.text ?? "",
    typeof parsed.text === "string" ? parsed.text : "",
    typeof parsed.html === "string" ? parsed.html : "",
  ].join("\n").trim();

  const hiddenText = hiddenSections.map((s) => s.content).join("\n");

  // Fail closed. Content that isn't valid RFC822 parses to nothing, and passing an
  // empty extraction downstream means the scan sees no text and allows anything —
  // so anything unparseable would bypass the firewall entirely. Scan the raw input.
  if (!visibleText && !hiddenText) {
    const raw = typeof content === "string" ? content : content.toString("utf8");
    return {
      visibleText: raw,
      hiddenText: "",
      provenance: { source: "email", hiddenSections: [{ type: "unparsed_raw", content: raw }] },
    };
  }

  return {
    visibleText,
    hiddenText,
    provenance: { source: "email", hiddenSections },
  };
}
