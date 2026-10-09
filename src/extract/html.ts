import * as cheerio from "cheerio";
import type { ExtractResult } from "./types.ts";

const HIDDEN_CSS = /display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0/i;
const OFFSCREEN_CSS = /position\s*:\s*absolute.{0,60}left\s*:\s*-\d{3,}px|left\s*:\s*-\d{3,}px.{0,60}position\s*:\s*absolute/i;

export async function extractHtml(content: string): Promise<ExtractResult> {
  const $ = cheerio.load(content);
  const hiddenSections: { type: string; content: string }[] = [];

  // HTML comments — invisible in rendered view
  $.root().find("*").addBack().contents().each((_, node) => {
    if (node.type === "comment") {
      const text = (node as cheerio.TextElement).data?.trim() ?? "";
      if (text) hiddenSections.push({ type: "html_comment", content: text });
    }
  });

  // CSS-hidden elements (display:none, visibility:hidden, font-size:0)
  $("[style]").each((_, el) => {
    const style = $(el).attr("style") ?? "";
    const text = $(el).text().trim();
    if (!text) return;
    if (HIDDEN_CSS.test(style)) {
      hiddenSections.push({ type: "css_hidden", content: text });
    } else if (OFFSCREEN_CSS.test(style)) {
      hiddenSections.push({ type: "offscreen", content: text });
    }
  });

  // Meta tag content
  $("meta[content]").each((_, el) => {
    const content = $(el).attr("content")?.trim() ?? "";
    if (content) hiddenSections.push({ type: "meta_content", content });
  });

  // Image alt text
  $("img[alt]").each((_, el) => {
    const alt = $(el).attr("alt")?.trim() ?? "";
    if (alt) hiddenSections.push({ type: "img_alt", content: alt });
  });

  // aria-label attributes
  $("[aria-label]").each((_, el) => {
    const label = $(el).attr("aria-label")?.trim() ?? "";
    if (label) hiddenSections.push({ type: "aria_label", content: label });
  });

  // noscript and template content — not rendered but parsed
  $("noscript, template").each((_, el) => {
    const text = $(el).text().trim();
    if (text) hiddenSections.push({ type: el.tagName, content: text });
  });

  const visibleText = $("body").text().trim();
  const hiddenText = hiddenSections.map((s) => s.content).join("\n");

  return {
    visibleText,
    hiddenText,
    provenance: { source: "html", hiddenSections },
  };
}
