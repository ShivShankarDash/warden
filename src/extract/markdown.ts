import { remark } from "remark";
import remarkParse from "remark-parse";
import { visit } from "unist-util-visit";
import type { ExtractResult } from "./types.ts";

export async function extractMarkdown(content: string): Promise<ExtractResult> {
  const tree = remark().use(remarkParse).parse(content);

  const visibleParts: string[] = [];
  const hiddenSections: { type: string; content: string }[] = [];

  visit(tree, (node: any) => {
    switch (node.type) {
      case "text":
        visibleParts.push(node.value);
        break;

      // Raw HTML blocks and inline HTML — comments and hidden spans live here
      case "html":
        hiddenSections.push({ type: "inline_html", content: node.value });
        break;

      // ![alt](url "title") — alt and title are invisible in rendered output
      case "image":
        if (node.alt) hiddenSections.push({ type: "image_alt", content: node.alt });
        if (node.title) hiddenSections.push({ type: "image_title", content: node.title });
        if (node.url) hiddenSections.push({ type: "image_url", content: node.url });
        break;

      // [text](url "title") — title attribute is invisible
      case "link":
        if (node.title) hiddenSections.push({ type: "link_title", content: node.title });
        break;

      // [ref]: url "title" — reference definitions. EchoLeak CVE-2025-32711 vector.
      case "definition":
        if (node.url) {
          hiddenSections.push({
            type: "reference_definition",
            content: `[${node.identifier ?? ""}]: ${node.url}${node.title ? ` "${node.title}"` : ""}`,
          });
        }
        break;
    }
  });

  const visibleText = visibleParts.join(" ").trim();
  const hiddenText = hiddenSections.map((s) => s.content).join("\n");

  return {
    visibleText,
    hiddenText,
    provenance: { source: "markdown", hiddenSections },
  };
}
