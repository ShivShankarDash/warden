/**
 * LLM client for the red-team agent.
 *
 * Mirrors the provider selection in src/detect/judge.ts (Anthropic native when an
 * Anthropic key is present, otherwise any OpenAI-compatible endpoint) so a single
 * .env configures both the defender and the attacker. Kept separate rather than
 * imported because the judge's module is tuned for short JSON verdicts — the
 * attacker needs longer, freer output and a different system prompt.
 */

type Provider = {
  kind: "anthropic" | "openai";
  apiKey: string;
  baseUrl: string;
  model: string;
  workspaceId?: string;
};

const TIMEOUT_MS = 30_000;

export function getProvider(): Provider | null {
  const anthropic = process.env.ANTHROPIC_API_KEY;
  if (anthropic) {
    return {
      kind: "anthropic",
      apiKey: anthropic,
      baseUrl: process.env.JUDGE_BASE_URL ?? "https://api.anthropic.com/v1",
      model: process.env.REDTEAM_MODEL ?? process.env.JUDGE_MODEL ?? "claude-haiku-4-5-20251001",
      workspaceId: process.env.ANTHROPIC_WORKSPACE_ID,
    };
  }
  const openai = process.env.OPENROUTER_API_KEY ?? process.env.OPENAI_API_KEY;
  if (openai) {
    return {
      kind: "openai",
      apiKey: openai,
      baseUrl: process.env.JUDGE_BASE_URL ?? "https://openrouter.ai/api/v1",
      model: process.env.REDTEAM_MODEL ?? "anthropic/claude-haiku-4.5",
    };
  }
  return null;
}

/** Counts every outbound LLM call, so the caller can enforce a hard budget. */
export class BudgetedClient {
  private used = 0;

  constructor(
    private provider: Provider,
    private budget: number
  ) {}

  get callsUsed() {
    return this.used;
  }
  get callsRemaining() {
    return Math.max(0, this.budget - this.used);
  }
  get exhausted() {
    return this.used >= this.budget;
  }

  async complete(system: string, user: string, maxTokens = 1200): Promise<string | null> {
    if (this.exhausted) return null;
    this.used++;

    const isAnthropic = this.provider.kind === "anthropic";
    try {
      const res = await fetch(
        `${this.provider.baseUrl}${isAnthropic ? "/messages" : "/chat/completions"}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(isAnthropic
              ? {
                  "x-api-key": this.provider.apiKey,
                  "anthropic-version": "2023-06-01",
                  ...(this.provider.workspaceId
                    ? { "anthropic-workspace-id": this.provider.workspaceId }
                    : {}),
                }
              : { Authorization: `Bearer ${this.provider.apiKey}` }),
          },
          body: JSON.stringify({
            model: this.provider.model,
            max_tokens: maxTokens,
            // Some variety is wanted here — a deterministic attacker explores nothing.
            temperature: 1,
            ...(isAnthropic
              ? { system, messages: [{ role: "user", content: user }] }
              : {
                  messages: [
                    { role: "system", content: system },
                    { role: "user", content: user },
                  ],
                }),
          }),
          signal: AbortSignal.timeout(TIMEOUT_MS),
        }
      );

      if (!res.ok) {
        console.error(`  [llm] ${res.status} ${res.statusText}: ${(await res.text()).slice(0, 160)}`);
        return null;
      }

      const body = await res.json();
      return isAnthropic
        ? (body?.content?.find((b: { type: string }) => b.type === "text")?.text ?? null)
        : (body?.choices?.[0]?.message?.content ?? null);
    } catch (e) {
      console.error(`  [llm] call failed: ${e instanceof Error ? e.message : e}`);
      return null;
    }
  }
}

/** Pulls a JSON array out of a model response that may be fenced or prefaced. */
export function parseJsonArray<T>(raw: string | null): T[] {
  if (!raw) return [];
  const cleaned = raw.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
  const start = cleaned.indexOf("[");
  const end = cleaned.lastIndexOf("]");
  if (start === -1 || end === -1) return [];
  try {
    const parsed = JSON.parse(cleaned.slice(start, end + 1));
    return Array.isArray(parsed) ? (parsed as T[]) : [];
  } catch {
    return [];
  }
}
