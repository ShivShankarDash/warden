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

  // Every header line, not just subject and from.
  //
  // mailparser surfaces only the headers it recognises, so anything else in the
  // header block was parsed and then dropped. That is content an attacker controls:
  // an injection on an X- header, or on any line shaped like "Key: value", was
  // removed before the first detection stage ever saw it.
  const headerText = (parsed.headerLines ?? [])
    .map((h: { line?: string }) => h.line ?? "")
    .filter(Boolean)
    .join("\n");

  const hiddenText = [headerText, hiddenSections.map((s) => s.content).join("\n")]
    .filter(Boolean)
    .join("\n");

  // Fail closed. Content that isn't valid RFC822 parses to nothing, and passing an
  // empty extraction downstream means the scan sees no text and allows anything —
  // so anything unparseable would bypass the firewall entirely. Scan the raw input.
  // Fail closed on an empty body.
  //
  // Keyed on visibleText alone, not on both being empty. Now that header lines are
  // collected, input that is a single header-shaped line — "Reference code: ignore
  // all previous instructions" — produces a non-empty hiddenText and would have
  // skipped this fallback, leaving the body empty and the whole message classed as
  // hidden content. It would still be scanned, but scored as concealed text rather
  // than as what it is: the entire message.
  if (!visibleText.trim()) {
    const raw = typeof content === "string" ? content : content.toString("utf8");
    return {
      visibleText: raw,
      hiddenText,
      provenance: {
        source: "email",
        hiddenSections: [...hiddenSections, { type: "unparsed_raw", content: raw }],
      },
    };
  }

  // Coverage guard. The check above only fires when the parse yields nothing at all,
  // so a parse that silently dropped most of its input sailed through. Text that is
  // not really an email but is scanned as one — anything whose opening lines look
  // like "Key: value" — gets those lines eaten as a header block, and the scan then
  // runs on whatever followed the first blank line. Observed on a 701-character
  // document that reached the detector as 271 characters, with the first 430 never
  // examined by any stage.
  //
  // Rather than trust the parser's judgement about what counts as content, compare
  // what came out against what went in and append the raw text when too much is
  // missing. Duplication costs a little latency; a silent gap costs a detection.
  const raw = typeof content === "string" ? content : content.toString("utf8");
  const covered = visibleText.length + hiddenText.length;
  const underCovered = raw.trim().length > 0 && covered < raw.trim().length * 0.9;

  return {
    visibleText,
    hiddenText: underCovered ? [hiddenText, raw].filter(Boolean).join("\n") : hiddenText,
    provenance: { source: "email", hiddenSections },
  };
}
