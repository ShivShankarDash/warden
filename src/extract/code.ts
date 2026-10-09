import type { ExtractResult } from "./types.ts";

const COMMENT_PATTERNS = [
  { type: "line_comment", re: /(?:\/\/|#|--|%)(.+)/g },
  { type: "block_comment", re: /\/\*[\s\S]*?\*\//g },
  { type: "docstring", re: /"""[\s\S]*?"""|'''[\s\S]*?'''/g },
  { type: "string_literal", re: /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g },
];

export async function extractCode(content: string): Promise<ExtractResult> {
  const hiddenSections: { type: string; content: string }[] = [];

  // [ME] after specs/02-extract.md: decide which patterns count as "hidden" injection surfaces
  for (const { type, re } of COMMENT_PATTERNS) {
    const matches = content.matchAll(re);
    for (const m of matches) {
      hiddenSections.push({ type, content: m[0] });
    }
  }

  const hiddenText = hiddenSections.map((s) => s.content).join("\n");

  return {
    visibleText: content,
    hiddenText,
    provenance: { source: "code", hiddenSections },
  };
}
