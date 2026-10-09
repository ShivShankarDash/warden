import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { scanPii } from "../src/guard/pii.ts";
import type { PiiScanResult } from "../src/guard/pii.ts";

/* ─── Helpers ─────────────────────────────────────────────────────────── */

/** Returns types from a scan result for easy assertion. */
const types = (r: PiiScanResult) => r.matches.map((m) => m.type);

/** Save and restore env vars around tests that modify them. */
let savedPiiEnabled: string | undefined;
let savedPiiTypes: string | undefined;

beforeEach(() => {
  savedPiiEnabled = process.env.WARDEN_PII_ENABLED;
  savedPiiTypes = process.env.WARDEN_PII_TYPES;
  // Ensure PII scanning is enabled by default for tests.
  delete process.env.WARDEN_PII_ENABLED;
  delete process.env.WARDEN_PII_TYPES;
});

afterEach(() => {
  if (savedPiiEnabled !== undefined) process.env.WARDEN_PII_ENABLED = savedPiiEnabled;
  else delete process.env.WARDEN_PII_ENABLED;
  if (savedPiiTypes !== undefined) process.env.WARDEN_PII_TYPES = savedPiiTypes;
  else delete process.env.WARDEN_PII_TYPES;
});

/* ─── Individual PII type detection ───────────────────────────────────── */

describe("pii — individual types", () => {
  test("detects IPv4 address", () => {
    const r = scanPii("Server at 10.0.0.1 is down");
    expect(r.hasPii).toBe(true);
    expect(r.matches).toHaveLength(1);
    expect(r.matches[0].type).toBe("ip_address");
    expect(r.matches[0].original).toBe("10.0.0.1");
    expect(r.mutatedContent).toBe("Server at [REDACTED_IP] is down");
  });

  test("detects email address", () => {
    const r = scanPii("Contact user@example.com for info");
    expect(r.hasPii).toBe(true);
    expect(r.matches).toHaveLength(1);
    expect(r.matches[0].type).toBe("email");
    expect(r.matches[0].original).toBe("user@example.com");
    expect(r.mutatedContent).toBe("Contact [REDACTED_EMAIL] for info");
  });

  test("detects US phone number", () => {
    const r = scanPii("Call me at 555-123-4567");
    expect(r.hasPii).toBe(true);
    expect(r.matches).toHaveLength(1);
    expect(r.matches[0].type).toBe("phone");
    expect(r.matches[0].original).toBe("555-123-4567");
    expect(r.mutatedContent).toBe("Call me at [REDACTED_PHONE]");
  });

  test("detects international phone number", () => {
    const r = scanPii("Reach me at +1-555-123-4567");
    expect(r.hasPii).toBe(true);
    expect(types(r)).toContain("phone");
    expect(r.mutatedContent).toContain("[REDACTED_PHONE]");
  });

  test("detects credit card number", () => {
    const r = scanPii("Card: 4111-1111-1111-1111");
    expect(r.hasPii).toBe(true);
    expect(r.matches[0].type).toBe("credit_card");
    expect(r.mutatedContent).toBe("Card: [REDACTED_CC]");
  });

  test("detects credit card without separators", () => {
    const r = scanPii("Card: 4111111111111111");
    expect(r.hasPii).toBe(true);
    expect(r.matches[0].type).toBe("credit_card");
  });

  test("detects SSN", () => {
    const r = scanPii("My SSN is 123-45-6789");
    expect(r.hasPii).toBe(true);
    expect(r.matches[0].type).toBe("ssn");
    expect(r.matches[0].original).toBe("123-45-6789");
    expect(r.mutatedContent).toBe("My SSN is [REDACTED_SSN]");
  });

  test("detects AWS access key", () => {
    const r = scanPii("Key: AKIA1234567890ABCDEF");
    expect(r.hasPii).toBe(true);
    expect(r.matches[0].type).toBe("aws_key");
    expect(r.matches[0].original).toBe("AKIA1234567890ABCDEF");
    expect(r.mutatedContent).toBe("Key: [REDACTED_AWS_KEY]");
  });

  test("detects API key (sk-*)", () => {
    const r = scanPii("sk-abc123def456ghi789jkl012");
    expect(r.hasPii).toBe(true);
    expect(r.matches[0].type).toBe("api_key");
    expect(r.mutatedContent).toBe("[REDACTED_API_KEY]");
  });

  test("detects API key (ghp_*)", () => {
    const r = scanPii("Token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345");
    expect(r.hasPii).toBe(true);
    expect(r.matches[0].type).toBe("api_key");
    expect(r.mutatedContent).toContain("[REDACTED_API_KEY]");
  });

  test("detects JWT", () => {
    const r = scanPii("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456");
    expect(r.hasPii).toBe(true);
    expect(r.matches[0].type).toBe("jwt");
    expect(r.mutatedContent).toContain("[REDACTED_JWT]");
  });

  test("detects private key block", () => {
    const key = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF068wEJ7
-----END RSA PRIVATE KEY-----`;
    const r = scanPii(`Here is the key: ${key}`);
    expect(r.hasPii).toBe(true);
    expect(r.matches[0].type).toBe("private_key");
    expect(r.mutatedContent).toContain("[REDACTED_PRIVATE_KEY]");
    expect(r.mutatedContent).not.toContain("MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn");
  });

  test("detects machine hostname", () => {
    const r = scanPii("Host: ip-172-31-22-5.ec2.internal");
    expect(r.hasPii).toBe(true);
    expect(r.matches[0].type).toBe("hostname");
    expect(r.mutatedContent).toBe("Host: [REDACTED_HOSTNAME]");
  });
});

/* ─── Combined / multiple matches ─────────────────────────────────────── */

describe("pii — combined matches", () => {
  test("detects email and IP in the same text", () => {
    const r = scanPii("Contact me at user@example.com from 10.0.0.1");
    expect(r.hasPii).toBe(true);
    expect(r.matches).toHaveLength(2);
    const matchTypes = types(r).sort();
    expect(matchTypes).toEqual(["email", "ip_address"]);
    expect(r.mutatedContent).toBe("Contact me at [REDACTED_EMAIL] from [REDACTED_IP]");
  });

  test("detects both US and international phone numbers", () => {
    const r = scanPii("Call me at 555-123-4567 or +1-555-123-4567");
    expect(r.hasPii).toBe(true);
    // Both should be detected as phone type.
    const phoneMatches = r.matches.filter((m) => m.type === "phone");
    expect(phoneMatches.length).toBeGreaterThanOrEqual(1);
    expect(r.mutatedContent).toContain("[REDACTED_PHONE]");
  });

  test("detects multiple instances of the same type", () => {
    const r = scanPii("Servers: 10.0.0.1 and 192.168.1.1");
    expect(r.hasPii).toBe(true);
    const ips = r.matches.filter((m) => m.type === "ip_address");
    expect(ips).toHaveLength(2);
    expect(r.mutatedContent).toBe("Servers: [REDACTED_IP] and [REDACTED_IP]");
  });
});

/* ─── Overlap resolution ──────────────────────────────────────────────── */

describe("pii — overlap resolution", () => {
  test("overlapping matches resolved without duplicate replacements", () => {
    // SSN and phone overlap: 123-45-6789 matches both SSN and could match phone patterns.
    // The resolved set should not produce garbled output.
    const r = scanPii("SSN: 123-45-6789");
    expect(r.hasPii).toBe(true);
    // Should get a clean replacement, not doubled.
    expect(r.mutatedContent).not.toContain("[REDACTED_SSN][REDACTED_");
    expect(r.mutatedContent).not.toContain("][REDACTED_");
  });

  test("adjacent but non-overlapping matches both survive", () => {
    const r = scanPii("user@test.com 10.0.0.1");
    expect(r.hasPii).toBe(true);
    expect(r.matches).toHaveLength(2);
    expect(r.mutatedContent).toBe("[REDACTED_EMAIL] [REDACTED_IP]");
  });
});

/* ─── No PII ──────────────────────────────────────────────────────────── */

describe("pii — clean text", () => {
  test("text with no PII returns hasPii false and original content", () => {
    const text = "The quick brown fox jumps over the lazy dog.";
    const r = scanPii(text);
    expect(r.hasPii).toBe(false);
    expect(r.matches).toHaveLength(0);
    expect(r.mutatedContent).toBe(text);
  });

  test("empty string returns hasPii false", () => {
    const r = scanPii("");
    expect(r.hasPii).toBe(false);
    expect(r.matches).toHaveLength(0);
    expect(r.mutatedContent).toBe("");
  });
});

/* ─── WARDEN_PII_TYPES filtering ─────────────────────────────────────── */

describe("pii — type filtering via WARDEN_PII_TYPES", () => {
  test("only detects specified types", () => {
    process.env.WARDEN_PII_TYPES = "ip_address,email";
    const r = scanPii("IP: 10.0.0.1, email: a@b.com, phone: 555-123-4567");
    expect(r.hasPii).toBe(true);
    const matchTypes = types(r);
    expect(matchTypes).toContain("ip_address");
    expect(matchTypes).toContain("email");
    expect(matchTypes).not.toContain("phone");
    expect(r.mutatedContent).toContain("[REDACTED_IP]");
    expect(r.mutatedContent).toContain("[REDACTED_EMAIL]");
    expect(r.mutatedContent).toContain("555-123-4567"); // phone not redacted
  });
});

/* ─── WARDEN_PII_ENABLED toggle ──────────────────────────────────────── */

describe("pii — disabled via WARDEN_PII_ENABLED", () => {
  test("returns original content when disabled", () => {
    process.env.WARDEN_PII_ENABLED = "0";
    const text = "My SSN is 123-45-6789";
    const r = scanPii(text);
    expect(r.hasPii).toBe(false);
    expect(r.matches).toHaveLength(0);
    expect(r.mutatedContent).toBe(text);
  });
});

/* ─── Edge cases ──────────────────────────────────────────────────────── */

describe("pii — edge cases", () => {
  test("version numbers like 1.2.3.4 match as IPv4 (known limitation)", () => {
    // The spec documents this: version-like strings trigger IPv4 regex.
    const r = scanPii("Version 1.2.3.4 released");
    expect(r.hasPii).toBe(true);
    expect(r.matches[0].type).toBe("ip_address");
  });

  test("AWS secret key near 'secret' keyword is detected", () => {
    const r = scanPii("secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1");
    expect(r.hasPii).toBe(true);
    expect(types(r)).toContain("aws_secret");
    expect(r.mutatedContent).toContain("[REDACTED_AWS_SECRET]");
  });

  test("repeated scans produce consistent results", () => {
    const text = "Email: test@abc.com IP: 192.168.0.1";
    const r1 = scanPii(text);
    const r2 = scanPii(text);
    expect(r1.mutatedContent).toBe(r2.mutatedContent);
    expect(r1.matches.length).toBe(r2.matches.length);
  });
});
