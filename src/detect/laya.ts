import type { Finding } from "../types.ts";

const LAYA_URL = process.env.LAYA_URL ?? "http://localhost:8111";
const LAYA_TIMEOUT = Number(process.env.LAYA_TIMEOUT ?? 5000);

// --- Health monitoring state ---
let _available = false;
let _lastCheck = 0;
let _consecutiveFailures = 0;

/** Snapshot of the Laya sidecar's health as seen by this process. */
export function layaStatus() {
  return { available: _available, lastCheck: _lastCheck, consecutiveFailures: _consecutiveFailures };
}

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
      const wasFirst = _consecutiveFailures === 0;
      _consecutiveFailures++;
      _available = false;
      _lastCheck = Date.now();
      if (wasFirst) {
        console.warn("[warden] Laya sidecar unavailable, falling back to PG2");
      }
      return { findings: [], benignScore: null, injectionProbability: 0 };
    }

    // Successful response — mark healthy.
    _available = true;
    _consecutiveFailures = 0;
    _lastCheck = Date.now();

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
    const wasFirst = _consecutiveFailures === 0;
    _consecutiveFailures++;
    _available = false;
    _lastCheck = Date.now();
    if (wasFirst) {
      console.warn("[warden] Laya sidecar unavailable, falling back to PG2");
    }
    return { findings: [], benignScore: null, injectionProbability: 0 };
  }
}
