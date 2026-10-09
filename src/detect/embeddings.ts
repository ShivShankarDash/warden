/**
 * Sentence embeddings for the similarity stage.
 *
 * MiniLM runs in ~2ms against the judge's ~1500ms, which is the entire point: once
 * the judge has confirmed an attack, matching its shape again should be cheap.
 */
type FeatureExtractionPipeline = (
  text: string,
  opts?: { pooling?: string; normalize?: boolean }
) => Promise<{ data: Float32Array | number[] }>;

const MODEL_ID = process.env.EMBEDDING_MODEL ?? "Xenova/all-MiniLM-L6-v2";
export const EMBEDDING_DIMS = 384;

let _pipeline: FeatureExtractionPipeline | null = null;
let _initPromise: Promise<void> | null = null;
let _initFailed = false;

export async function initEmbeddings(): Promise<void> {
  if (_pipeline || _initFailed) return;
  if (_initPromise) return _initPromise;

  _initPromise = (async () => {
    try {
      const { pipeline, env } = await import("@huggingface/transformers");
      env.allowLocalModels = false;
      env.useBrowserCache = false;
      console.log(`Loading embedding model (${MODEL_ID})...`);
      _pipeline = (await pipeline("feature-extraction", MODEL_ID, {
        dtype: "q8",
      } as Record<string, unknown>)) as unknown as FeatureExtractionPipeline;
      console.log("Embedding model loaded.");
    } catch (e) {
      console.warn(`Embedding init failed — similarity stage disabled: ${e instanceof Error ? e.message : e}`);
      _initFailed = true;
    }
  })();

  return _initPromise;
}

export function embeddingsAvailable(): boolean {
  return _pipeline !== null;
}

/** Returns a unit-length vector, or null when the model is unavailable. */
export async function embed(text: string): Promise<Float32Array | null> {
  if (!_pipeline) return null;
  try {
    const out = await _pipeline(text.slice(0, 2000), { pooling: "mean", normalize: true });
    return out.data instanceof Float32Array ? out.data : new Float32Array(out.data);
  } catch (e) {
    console.warn(`Embedding failed: ${e instanceof Error ? e.message : e}`);
    return null;
  }
}

/** Both vectors are already normalised, so the dot product is the cosine. */
export function cosine(a: Float32Array, b: Float32Array): number {
  const n = Math.min(a.length, b.length);
  let sum = 0;
  for (let i = 0; i < n; i++) sum += a[i] * b[i];
  return sum;
}

export function toBlob(v: Float32Array): Uint8Array {
  return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
}

export function fromBlob(b: Uint8Array): Float32Array {
  // Copy rather than view: the row buffer may not be 4-byte aligned.
  return new Float32Array(new Uint8Array(b).buffer.slice(0));
}
