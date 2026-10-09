import type { ExtractResult } from "./types.ts";

function walkJson(val: unknown, parts: string[]): void {
  if (typeof val === "string") {
    parts.push(val);
  } else if (Array.isArray(val)) {
    for (const item of val) walkJson(item, parts);
  } else if (val !== null && typeof val === "object") {
    for (const v of Object.values(val as Record<string, unknown>)) walkJson(v, parts);
  }
}

export async function extractJson(content: string): Promise<ExtractResult> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return {
      visibleText: content,
      hiddenText: "",
      provenance: { source: "api_json", hiddenSections: [] },
    };
  }

  const parts: string[] = [];
  walkJson(parsed, parts);
  const visibleText = parts.join("\n").trim();

  // api_json: no structural hiding — all string values are equally suspicious
  return {
    visibleText,
    hiddenText: "",
    provenance: { source: "api_json", hiddenSections: [] },
  };
}
