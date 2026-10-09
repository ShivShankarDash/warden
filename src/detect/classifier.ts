import type { Finding } from "../types.ts";

type LabelScore = { label: string; score: number };
type TextClassificationPipeline = (
  text: string | string[],
  opts?: { top_k?: number }
) => Promise<LabelScore | LabelScore[]>;

let _pipeline: TextClassificationPipeline | null = null;
let _initPromise: Promise<void> | null = null;
let _initFailed = false;

// This repo keeps its .onnx files at the repo root; transformers.js defaults to
// looking under onnx/, so subfolder must be "". The onnx-community mirror is
// gated behind Meta's Llama license and 401s without an HF token.
const MODEL_CANDIDATES: { id: string; dtype: "q8" | "fp32"; subfolder: string }[] = [
  { id: "gravitee-io/Llama-Prompt-Guard-2-22M-onnx", dtype: "fp32", subfolder: "" },
  { id: "onnx-community/Llama-Prompt-Guard-2-22M-ONNX", dtype: "q8", subfolder: "onnx" },
];

const MODEL_OVERRIDE = process.env.PROMPT_GUARD_MODEL;

// Max input length — Prompt Guard 2 is trained on shorter sequences
const MAX_TOKENS = 512;

/** Fallback when no policy threshold is passed. Per specs/04-detect.md: 0.6 rather
 *  than 0.5, to reduce over-triggering on benign text. */
const CLASSIFIER_THRESHOLD = 0.6;

export async function initClassifier(): Promise<void> {
  if (_pipeline || _initFailed) return;
  if (_initPromise) return _initPromise;

  _initPromise = (async () => {
    const { pipeline, env } = await import("@huggingface/transformers");
    env.allowLocalModels = false;
    env.useBrowserCache = false;

    const candidates = MODEL_OVERRIDE
      ? [{ id: MODEL_OVERRIDE, dtype: "fp32" as const, subfolder: "" }]
      : MODEL_CANDIDATES;

    for (const { id, dtype, subfolder } of candidates) {
      try {
        console.log(`Loading Prompt Guard 2 (${id}, dtype=${dtype})...`);
        _pipeline = (await pipeline("text-classification", id, {
          dtype,
          subfolder,
        } as Record<string, unknown>)) as unknown as TextClassificationPipeline;
        console.log(`Prompt Guard 2 loaded (${id}, dtype=${dtype}).`);
        return;
      } catch (e) {
        console.warn(`  ${id} (${dtype}) unavailable: ${e instanceof Error ? e.message : e}`);
      }
    }

    console.warn("Classifier init failed — all candidates exhausted. Running rules-only.");
    _initFailed = true;
  })();

  return _initPromise;
}

// Label naming varies by conversion: gravitee-io emits MALICIOUS/BENIGN,
// others use INJECTION/SAFE or the unmapped LABEL_1/LABEL_0.
function labelIsInjection(label: string): boolean {
  const l = label.toUpperCase();
  return l === "MALICIOUS" || l === "INJECTION" || l === "UNSAFE" || l === "LABEL_1" || l === "1";
}

export interface ClassifierResult {
  findings: Finding[];
  /**
   * How confident the model is that the text is benign, or null when the classifier
   * did not run. Benign text scores ~0.999 regardless of language, so anything
   * meaningfully below that is the model hedging rather than clearing the content —
   * which is the signal that catches attacks it has no confident opinion about
   * (non-English phrasings, adversarial suffixes, novel wordings).
   */
  benignScore: number | null;
}

export async function classify(
  text: string,
  threshold = CLASSIFIER_THRESHOLD
): Promise<ClassifierResult> {
  if (!_pipeline) return { findings: [], benignScore: null };

  // Truncate to avoid blowing past the model's context window
  const input = text.slice(0, MAX_TOKENS * 4); // rough char estimate

  try {
    const raw = await _pipeline(input, { top_k: 2 });
    const results = Array.isArray(raw) ? raw : [raw];

    const malicious = results.find((r) => labelIsInjection(r.label));
    const benign = results.find((r) => !labelIsInjection(r.label));
    // Binary model, so one score implies the other when only the top label came back.
    const benignScore = benign?.score ?? (malicious ? 1 - malicious.score : null);

    if (!malicious || malicious.score < threshold) {
      return { findings: [], benignScore };
    }

    return {
      benignScore,
      findings: [
        {
          // Prompt Guard 2 is binary — attack type refined by judge if needed
          attackType: "instruction_override",
          confidence: malicious.score,
          stage: "classifier",
          spans: [],
          reason: `Prompt Guard 2: label=${malicious.label}, score=${malicious.score.toFixed(3)}`,
        },
      ],
    };
  } catch (e) {
    console.warn(`Classifier inference error: ${e}`);
    return { findings: [], benignScore: null };
  }
}
