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
