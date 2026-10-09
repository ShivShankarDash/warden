import type { SourceType } from "../types.ts";

export interface ExtractResult {
  visibleText: string;
  hiddenText: string;
  provenance: {
    source: SourceType;
    hiddenSections: { type: string; content: string }[];
  };
}
