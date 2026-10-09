import type { Finding } from "../types.ts";

const LAYA_URL = process.env.LAYA_URL ?? "http://localhost:8111";
const LAYA_TIMEOUT = Number(process.env.LAYA_TIMEOUT ?? 5000);

export interface LayaResult {
  findings: Finding[];
  benignScore: number | null;
  injectionProbability: number;
}

/**
 * Classify text via the Laya sidecar HTTP server. Returns calibrated injection
 * probability from the fine-tuned ModernBERT-large model.
 *
 * On ANY error (server down, timeout, bad response) returns a safe fallback and
 * never throws — the caller uses benignScore === null && injectionProbability === 0
 * to detect that Laya did not run and should fall back to Prompt Guard 2.
 */
export async function classifyWithLaya(
  text: string,
  threshold = 0.75
): Promise<LayaResult> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), LAYA_TIMEOUT);

    const res = await fetch(`${LAYA_URL}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!res.ok) {
      return { findings: [], benignScore: null, injectionProbability: 0 };
    }

    const data = (await res.json()) as {
      injection_probability: number;
      attack_type: string;
      is_attack: boolean;
    };

    const prob = data.injection_probability;
    const benignScore = 1 - prob;

    if (prob < threshold) {
      return { findings: [], benignScore, injectionProbability: prob };
    }

    return {
      benignScore,
      injectionProbability: prob,
      findings: [
        {
          attackType: "instruction_override",
          confidence: prob,
          stage: "classifier",
          spans: [],
          reason: `Laya: injection_probability=${prob.toFixed(3)}`,
        },
      ],
    };
  } catch {
    // Server down, timeout, network error, bad JSON — all handled identically.
    return { findings: [], benignScore: null, injectionProbability: 0 };
  }
}
