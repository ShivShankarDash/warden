/**
 * Threat intelligence fetcher — pulls new items from remote sources.
 *
 * Each source type (HuggingFace dataset, GitHub repo) has a dedicated fetch
 * function that handles pagination, deduplication via last-seen offsets, and
 * graceful error handling. State is persisted in the intel_sources table so
 * fetches resume where they left off across restarts.
 */

import { getDb } from "../store/db.ts";
import type { IntelSource, IntelItem } from "./sources.ts";

const FETCH_TIMEOUT_MS = 15_000;

// ---------------------------------------------------------------------------
// Source state (intel_sources table)
// ---------------------------------------------------------------------------

export interface SourceState {
  lastFetchedAt: number | null;
  lastRowCount: number | null;
  itemsFetched: number;
  errors: number;
}

/**
 * Reads persisted state for a source. Returns sensible defaults when the
 * source has never been fetched.
 */
export function getSourceState(sourceId: string): SourceState {
  const db = getDb();
  const row = db
    .query(
      "SELECT last_fetched_at, last_row_count, items_fetched, errors FROM intel_sources WHERE source_id = ?"
    )
    .get(sourceId) as Record<string, any> | null;

  if (!row) {
    return { lastFetchedAt: null, lastRowCount: null, itemsFetched: 0, errors: 0 };
  }
  return {
    lastFetchedAt: row.last_fetched_at ?? null,
    lastRowCount: row.last_row_count ?? null,
    itemsFetched: row.items_fetched ?? 0,
    errors: row.errors ?? 0,
  };
}

/**
 * Upserts source state. Always bumps updated_at.
 */
export function updateSourceState(
  sourceId: string,
  patch: {
    lastFetchedAt?: number;
    lastRowCount?: number;
    itemsFetched?: number;
    errors?: number;
  }
): void {
  const db = getDb();
  const now = Date.now();
  const current = getSourceState(sourceId);

  db.prepare(
    `INSERT INTO intel_sources (source_id, last_fetched_at, last_row_count, items_fetched, errors, updated_at)
     VALUES ($sourceId, $lastFetchedAt, $lastRowCount, $itemsFetched, $errors, $updatedAt)
     ON CONFLICT(source_id) DO UPDATE SET
       last_fetched_at = $lastFetchedAt,
       last_row_count = $lastRowCount,
       items_fetched = $itemsFetched,
       errors = $errors,
       updated_at = $updatedAt`
  ).run({
    $sourceId: sourceId,
    $lastFetchedAt: patch.lastFetchedAt ?? current.lastFetchedAt,
    $lastRowCount: patch.lastRowCount ?? current.lastRowCount,
    $itemsFetched: patch.itemsFetched ?? current.itemsFetched,
    $errors: patch.errors ?? current.errors,
    $updatedAt: now,
  });
}

// ---------------------------------------------------------------------------
// Fetchers
// ---------------------------------------------------------------------------

/**
 * Fetches new rows from a HuggingFace dataset API. Uses offset/length pagination
 * so only unseen rows are returned.
 */
export async function fetchHuggingFace(
  source: IntelSource,
  state: SourceState
): Promise<IntelItem[]> {
  const offset = state.lastRowCount ?? 0;
  const url = `${source.url}&offset=${offset}&length=100`;

  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!res.ok) {
      console.error(`[intel] HF fetch failed for ${source.name}: ${res.status} ${res.statusText}`);
      return [];
    }
    const body = await res.json();
    return source.parser(body);
  } catch (e) {
    console.error(`[intel] HF fetch error for ${source.name}: ${e instanceof Error ? e.message : e}`);
    return [];
  }
}

/**
 * Fetches new items from a GitHub API endpoint. Filters results to items
 * newer than the last fetch timestamp.
 */
export async function fetchGitHub(
  source: IntelSource,
  state: SourceState
): Promise<IntelItem[]> {
  try {
    const res = await fetch(source.url, {
      headers: { Accept: "application/vnd.github.v3+json" },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!res.ok) {
      console.error(`[intel] GitHub fetch failed for ${source.name}: ${res.status} ${res.statusText}`);
      return [];
    }
    const body = await res.json();
    const items = source.parser(body);

    // Filter to items newer than last fetch
    if (state.lastFetchedAt) {
      return items.filter((item) => item.fetchedAt > state.lastFetchedAt!);
    }
    return items;
  } catch (e) {
    console.error(`[intel] GitHub fetch error for ${source.name}: ${e instanceof Error ? e.message : e}`);
    return [];
  }
}

/**
 * Fetches new items from any supported source type. Reads/writes persisted state
 * so the next run picks up where this one left off.
 */
export async function fetchSource(source: IntelSource): Promise<IntelItem[]> {
  const state = getSourceState(source.name);
  let items: IntelItem[];

  try {
    if (source.type === "huggingface_dataset") {
      items = await fetchHuggingFace(source, state);
    } else if (source.type === "github_repo") {
      items = await fetchGitHub(source, state);
    } else {
      console.warn(`[intel] Unsupported source type: ${source.type}`);
      return [];
    }

    // Update state on success
    updateSourceState(source.name, {
      lastFetchedAt: Date.now(),
      lastRowCount: (state.lastRowCount ?? 0) + items.length,
      itemsFetched: (state.itemsFetched ?? 0) + items.length,
    });

    return items;
  } catch (e) {
    // Update error count on failure
    updateSourceState(source.name, {
      errors: (state.errors ?? 0) + 1,
    });
    console.error(`[intel] fetchSource error for ${source.name}: ${e instanceof Error ? e.message : e}`);
    return [];
  }
}
