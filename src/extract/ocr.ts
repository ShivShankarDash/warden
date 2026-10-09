import type { ExtractResult } from "./types.ts";

let worker: Awaited<ReturnType<typeof import("tesseract.js").createWorker>> | null = null;

async function getWorker() {
  if (!worker) {
    const { createWorker } = await import("tesseract.js");
    worker = await createWorker("eng");
  }
  return worker;
}

export async function extractOcr(imageBytes: Uint8Array): Promise<ExtractResult> {
  const w = await getWorker();
  const { data } = await w.recognize(imageBytes);
  const visibleText = data.text.trim();

  return {
    visibleText,
    hiddenText: "",
    provenance: { source: "image", hiddenSections: [] },
  };
}
