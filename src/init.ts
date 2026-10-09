import { initClassifier } from "./detect/classifier.ts";
import { initEmbeddings } from "./detect/embeddings.ts";
import { getDb } from "./store/db.ts";
import { migrateLegacyReferences, migrateMemoryConstraints } from "./store/memory.ts";

export async function initWarden(): Promise<void> {
  getDb(); // create tables if needed
  if (migrateMemoryConstraints()) console.log("Rebuilt memory table for new origin values.");
  const migrated = migrateLegacyReferences();
  if (migrated) console.log(`Migrated ${migrated} legacy references into memory.`);
  // Both models load once at startup rather than per request. Loaded in parallel
  // since neither depends on the other, and both fail soft.
  await Promise.all([initClassifier(), initEmbeddings()]);
}
