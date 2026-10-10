#!/usr/bin/env python3
"""
Benchmark Warden against public prompt injection datasets.

Requires:
  - Warden API running on localhost:3000 (bun src/cli.ts --api-only --port 3000)
  - pip install datasets

Usage:
  python3 eval/benchmark-public.py
"""
import json, time, sys, os
from collections import defaultdict

try:
    import requests
except ImportError:
    print("Installing requests...")
    os.system(f"{sys.executable} -m pip install -q requests")
    import requests

try:
    from datasets import load_dataset
except ImportError:
    print("Installing datasets...")
    os.system(f"{sys.executable} -m pip install -q datasets")
    from datasets import load_dataset

WARDEN_URL = os.environ.get("WARDEN_URL", "http://localhost:3000")
API_KEY = os.environ.get("WARDEN_API_KEY", "")

# Check Warden is reachable
try:
    r = requests.get(f"{WARDEN_URL}/metrics", timeout=5)
    r.raise_for_status()
    print(f"✅ Warden reachable at {WARDEN_URL}\n")
except Exception as e:
    print(f"❌ Warden not reachable at {WARDEN_URL}: {e}")
    print("   Start it with: bun src/cli.ts --api-only --port 3000")
    sys.exit(1)

def scan(text, source="user_message", agent_id="benchmark"):
    """Send text to Warden and return the result."""
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["X-API-Key"] = API_KEY
    try:
        r = requests.post(
            f"{WARDEN_URL}/scan",
            json={"content": text, "source": source, "agentId": agent_id},
            headers=headers,
            timeout=15,
        )
        return r.json()
    except Exception as e:
        return {"action": "ERROR", "error": str(e)}

# ── Results tracking ──────────────────────────────────────────────────
results = defaultdict(lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "total": 0, "errors": 0, "total_ms": 0})

def record(dataset_name, expected_attack, result):
    r = results[dataset_name]
    r["total"] += 1
    
    action = result.get("action", "ERROR")
    if action == "ERROR":
        r["errors"] += 1
        return
    
    # Latency
    trace = result.get("trace", [])
    total_entry = next((t for t in trace if t.get("stage") == "total"), None)
    if total_entry:
        r["total_ms"] += total_entry.get("ms", 0)
    
    detected = action in ("BLOCK", "QUARANTINE", "HUMAN_REVIEW", "SANITIZE")
    
    if expected_attack and detected:
        r["tp"] += 1
    elif expected_attack and not detected:
        r["fn"] += 1
    elif not expected_attack and detected:
        r["fp"] += 1
    else:
        r["tn"] += 1

def print_results():
    print("\n" + "=" * 80)
    print(f"{'DATASET':<35} {'ACC':>6} {'PREC':>6} {'REC':>6} {'F1':>6} {'FP%':>6} {'AVG ms':>7} {'N':>6}")
    print("=" * 80)
    
    grand = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "total": 0, "errors": 0, "total_ms": 0}
    
    for name, r in sorted(results.items()):
        total = r["tp"] + r["fp"] + r["tn"] + r["fn"]
        if total == 0:
            print(f"{name:<35} {'—':>6} {'—':>6} {'—':>6} {'—':>6} {'—':>6} {'—':>7} {r['total']:>6}")
            continue
        
        acc = (r["tp"] + r["tn"]) / total
        prec = r["tp"] / max(1, r["tp"] + r["fp"])
        rec = r["tp"] / max(1, r["tp"] + r["fn"])
        f1 = 2 * prec * rec / max(1e-9, prec + rec)
        fpr = r["fp"] / max(1, r["fp"] + r["tn"])
        avg_ms = r["total_ms"] / max(1, total)
        
        print(f"{name:<35} {acc:>5.1%} {prec:>5.1%} {rec:>5.1%} {f1:>5.1%} {fpr:>5.1%} {avg_ms:>6.0f}ms {total:>6}")
        
        for k in grand:
            grand[k] += r[k]
    
    total = grand["tp"] + grand["fp"] + grand["tn"] + grand["fn"]
    if total:
        acc = (grand["tp"] + grand["tn"]) / total
        prec = grand["tp"] / max(1, grand["tp"] + grand["fp"])
        rec = grand["tp"] / max(1, grand["tp"] + grand["fn"])
        f1 = 2 * prec * rec / max(1e-9, prec + rec)
        fpr = grand["fp"] / max(1, grand["fp"] + grand["tn"])
        avg_ms = grand["total_ms"] / max(1, total)
        
        print("-" * 80)
        print(f"{'TOTAL':<35} {acc:>5.1%} {prec:>5.1%} {rec:>5.1%} {f1:>5.1%} {fpr:>5.1%} {avg_ms:>6.0f}ms {total:>6}")
    
    print(f"\n  TP={grand['tp']} FP={grand['fp']} TN={grand['tn']} FN={grand['fn']} Errors={grand['errors']}")
    print(f"  PII redactions will show in the Warden terminal output.")

# ── Dataset loading and scanning ──────────────────────────────────────

def run_dataset(name, loader_fn, max_samples=500):
    """Load a dataset, scan each sample, track results."""
    print(f"\n{'─' * 60}")
    print(f"📊 {name}")
    print(f"{'─' * 60}")
    try:
        samples = loader_fn()
        count = 0
        for text, is_attack in samples:
            if not text or len(text.strip()) < 5:
                continue
            if count >= max_samples:
                break
            result = scan(text)
            record(name, is_attack, result)
            count += 1
            if count % 50 == 0:
                r = results[name]
                print(f"  ... {count} scanned (TP={r['tp']} FP={r['fp']} TN={r['tn']} FN={r['fn']})")
        
        r = results[name]
        total = r["tp"] + r["fp"] + r["tn"] + r["fn"]
        if total:
            acc = (r["tp"] + r["tn"]) / total
            print(f"  ✅ {count} samples | Accuracy: {acc:.1%} | TP={r['tp']} FP={r['fp']} TN={r['tn']} FN={r['fn']}")
        else:
            print(f"  ⚠️  No valid samples processed")
    except Exception as e:
        print(f"  ❌ Failed: {e}")

# ── Dataset loaders ───────────────────────────────────────────────────

def load_deepset():
    ds = load_dataset("deepset/prompt-injections", split="train")
    for row in ds:
        text = row.get("text", "").strip()
        is_attack = row.get("label", 0) == 1
        yield text, is_attack

def load_notinject():
    ds = load_dataset("leolee99/NotInject", split="train")
    for row in ds:
        text = str(row.get("text", row.get("prompt", row.get("content", "")))).strip()
        yield text, False  # All benign

def load_antijection():
    ds = load_dataset("Antijection/prompt-injection-dataset-v1", split="train")
    for row in ds:
        text = str(row.get("text", row.get("prompt", ""))).strip()
        label = row.get("label", 0)
        is_attack = label == 1 or str(label).lower() in ("1", "injection", "malicious")
        yield text, is_attack

def load_neuralchemy():
    ds = load_dataset("neuralchemy/Prompt-injection-dataset", split="train")
    for row in ds:
        text = str(row.get("text", "")).strip()
        label = row.get("label", 0)
        is_attack = label == 1 or str(label).lower() in ("1", "injection", "malicious")
        yield text, is_attack

def load_safeguard():
    ds = load_dataset("xTRam1/safe-guard-prompt-injection", split="train")
    for row in ds:
        text = str(row.get("text", "")).strip()
        is_attack = row.get("label", 0) == 1
        yield text, is_attack

def load_hse():
    ds = load_dataset("hse-llm/prompt-injections", split="train")
    for row in ds:
        text = str(row.get("text", row.get("prompt", ""))).strip()
        label = row.get("label", 0)
        is_attack = label == 1 or str(label).lower() in ("1", "injection", "malicious")
        yield text, is_attack

# ── Run all datasets ──────────────────────────────────────────────────

print("=" * 60)
print("🛡  WARDEN BENCHMARK — Public Prompt Injection Datasets")
print("=" * 60)
print(f"API: {WARDEN_URL}")
print(f"Max samples per dataset: 500")
print(f"Watch your Warden terminal for live scan output!\n")

t_start = time.time()

run_dataset("deepset/prompt-injections",     load_deepset,     max_samples=500)
run_dataset("NotInject (all benign)",         load_notinject,   max_samples=339)
run_dataset("Antijection/eval-suite",         load_antijection, max_samples=500)
run_dataset("neuralchemy/PromptSentinel",     load_neuralchemy, max_samples=500)
run_dataset("xTRam1/safe-guard",              load_safeguard,   max_samples=500)
run_dataset("hse-llm/prompt-injections",      load_hse,         max_samples=500)

elapsed = time.time() - t_start
print_results()
print(f"\n  Total time: {elapsed:.0f}s ({elapsed/60:.1f} min)")

# Save results
output = {
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    "datasets": {name: dict(r) for name, r in results.items()},
    "elapsed_s": round(elapsed, 1),
}
out_path = "eval/results/benchmark-public.json"
os.makedirs(os.path.dirname(out_path), exist_ok=True)
with open(out_path, "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Results saved to {out_path}")
