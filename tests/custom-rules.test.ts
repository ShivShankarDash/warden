import { describe, expect, test, beforeEach, afterAll } from "bun:test";
import { writeFileSync, unlinkSync, mkdirSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import {
  loadCustomRules,
  applyCustomRules,
  resetCustomRulesCache,
} from "../src/detect/custom-rules.ts";

const TMP_DIR = join(tmpdir(), "warden-custom-rules-test");
const TMP_FILE = join(TMP_DIR, "test-rules.yaml");

function writeYaml(content: string): void {
  mkdirSync(TMP_DIR, { recursive: true });
  writeFileSync(TMP_FILE, content, "utf-8");
}

function cleanUp(): void {
  try {
    unlinkSync(TMP_FILE);
  } catch {
    // file may not exist
  }
}

beforeEach(() => {
  cleanUp();
  resetCustomRulesCache();
  process.env.WARDEN_CUSTOM_RULES = TMP_FILE;
});

afterAll(() => {
  cleanUp();
  delete process.env.WARDEN_CUSTOM_RULES;
  resetCustomRulesCache();
});

describe("custom-rules — loading", () => {
  test("loads rules from a YAML file", () => {
    writeYaml(`
rules:
  - name: test-rule
    pattern: "block\\\\s+this"
    attack_type: context_poisoning
    confidence: 0.80
`);
    const rules = loadCustomRules();
    expect(rules.length).toBe(1);
    expect(rules[0].name).toBe("test-rule");
    expect(rules[0].attackType).toBe("context_poisoning");
    expect(rules[0].confidence).toBe(0.80);
  });

  test("missing YAML file silently returns empty", () => {
    process.env.WARDEN_CUSTOM_RULES = "/nonexistent/path/rules.yaml";
    const rules = loadCustomRules();
    expect(rules).toEqual([]);
  });

  test("empty YAML file returns empty", () => {
    writeYaml("");
    const rules = loadCustomRules();
    expect(rules).toEqual([]);
  });

  test("YAML file with no rules key returns empty", () => {
    writeYaml("other_key: true");
    const rules = loadCustomRules();
    expect(rules).toEqual([]);
  });
});

describe("custom-rules — matching", () => {
  test("applyCustomRules returns findings for matching patterns", () => {
    writeYaml(`
rules:
  - name: block-acme
    pattern: "acme\\\\s+corp"
    attack_type: context_poisoning
    confidence: 0.85
`);
    const findings = applyCustomRules("Please contact acme corp for details.", "email");
    expect(findings.length).toBe(1);
    expect(findings[0].attackType).toBe("context_poisoning");
    expect(findings[0].confidence).toBe(0.85);
    expect(findings[0].reason).toContain("block-acme");
    expect(findings[0].stage).toBe("rules");
    expect(findings[0].spans.length).toBeGreaterThan(0);
  });

  test("non-matching text returns empty findings", () => {
    writeYaml(`
rules:
  - name: block-acme
    pattern: "acme\\\\s+corp"
    attack_type: context_poisoning
    confidence: 0.85
`);
    const findings = applyCustomRules("Nothing suspicious here.", "email");
    expect(findings).toEqual([]);
  });
});

describe("custom-rules — source_filter", () => {
  test("rule with source_filter only fires on matching sources", () => {
    writeYaml(`
rules:
  - name: html-only
    pattern: "evil\\\\s+script"
    attack_type: tool_abuse
    confidence: 0.90
    source_filter:
      - html
`);
    const html = applyCustomRules("evil script detected", "html");
    expect(html.length).toBe(1);

    resetCustomRulesCache();
    // Re-load since cache was reset
    const email = applyCustomRules("evil script detected", "email");
    expect(email).toEqual([]);
  });

  test("rule without source_filter fires on all sources", () => {
    writeYaml(`
rules:
  - name: catch-all
    pattern: "universal\\\\s+match"
    attack_type: instruction_override
    confidence: 0.75
`);
    for (const source of ["email", "html", "user_message", "pdf"] as const) {
      resetCustomRulesCache();
      const findings = applyCustomRules("universal match here", source);
      expect(findings.length).toBe(1);
    }
  });
});

describe("custom-rules — hot-reload", () => {
  test("detects file changes on next call", async () => {
    writeYaml(`
rules:
  - name: v1-rule
    pattern: "version_one"
    attack_type: context_poisoning
    confidence: 0.70
`);
    let findings = applyCustomRules("version_one text", "email");
    expect(findings.length).toBe(1);
    expect(findings[0].reason).toContain("v1-rule");

    // Small delay to ensure mtime changes (filesystem resolution)
    await new Promise((r) => setTimeout(r, 50));

    writeYaml(`
rules:
  - name: v2-rule
    pattern: "version_two"
    attack_type: tool_abuse
    confidence: 0.90
`);

    // Old pattern should no longer match after reload
    findings = applyCustomRules("version_one text", "email");
    expect(findings).toEqual([]);

    // New pattern should match
    findings = applyCustomRules("version_two text", "email");
    expect(findings.length).toBe(1);
    expect(findings[0].reason).toContain("v2-rule");
  });
});

describe("custom-rules — integration with applyRules", () => {
  test("custom rules fire alongside built-in rules via applyRules", async () => {
    // Import applyRules to verify the wiring
    const { applyRules } = await import("../src/detect/rules.ts");

    writeYaml(`
rules:
  - name: custom-integration
    pattern: "custom_marker_xyz"
    attack_type: context_poisoning
    confidence: 0.80
`);
    resetCustomRulesCache();

    const findings = applyRules("custom_marker_xyz", "email");
    const custom = findings.find((f) => f.reason.includes("custom-integration"));
    expect(custom).toBeDefined();
    expect(custom!.attackType).toBe("context_poisoning");
  });
});
