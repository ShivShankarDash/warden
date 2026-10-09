export interface DecodeResult {
  text: string;
  decodingApplied: string[];
  depth: number;
}

// ── Pre-processing (always applied) ────────────────────────────────────────
// These run before the encoding detectors and are recorded in decodingApplied:
// the fact that content *had* smuggled characters is evidence in its own right,
// and downstream stages can no longer observe it once it has been stripped.

function stripInvisibleUnicode(text: string): string {
  return text
    .replace(/[​-‍⁠﻿­]/g, "")  // zero-width + soft hyphen
    .replace(/\uDB40[\uDC00-\uDC7F]/g, "");               // tag chars U+E0000–U+E007F (surrogate pairs)
}

/**
 * Visually identical characters from other scripts, mapped back to Latin.
 *
 * Coverage here is load-bearing in a way that is easy to underestimate: a robustness
 * sweep found that omitting just two characters — Cyrillic і (U+0456) and ѕ (U+0455)
 * — let 55% of known attacks through, because "іgnore all prevіouѕ inѕtructionѕ"
 * no longer matches /ignore\s+.*instructions/i. A partial table is close to no table,
 * so this aims to cover the full set an attacker would reach for rather than the
 * handful that look obvious.
 */
const HOMOGLYPHS: Record<string, string> = {
  // Cyrillic lowercase
  а: "a", б: "6", в: "b", е: "e", з: "3", и: "u", й: "u", к: "k", м: "m",
  н: "h", о: "o", р: "p", с: "c", т: "t", у: "y", х: "x", ѕ: "s", і: "i",
  ј: "j", ԁ: "d", һ: "h", ԛ: "q", ԝ: "w", ѵ: "v", ҽ: "e", ο: "o",
  // Cyrillic uppercase
  А: "A", В: "B", Е: "E", Ѕ: "S", І: "I", Ј: "J", К: "K", М: "M", Н: "H",
  О: "O", Р: "P", С: "C", Т: "T", Х: "X", У: "Y", Ԍ: "G", Ԁ: "D",
  // Greek lowercase
  α: "a", β: "b", ε: "e", ι: "i", κ: "k", μ: "u", ν: "v", ο: "o", ρ: "p",
  σ: "o", τ: "t", υ: "u", χ: "x", γ: "y", ϲ: "c", ϳ: "j",
  // Greek uppercase
  Α: "A", Β: "B", Ε: "E", Ζ: "Z", Η: "H", Ι: "I", Κ: "K", Μ: "M", Ν: "N",
  Ο: "O", Ρ: "P", Τ: "T", Υ: "Y", Χ: "X",
  // Fullwidth forms
  ａ: "a", ｂ: "b", ｃ: "c", ｄ: "d", ｅ: "e", ｆ: "f", ｇ: "g", ｈ: "h",
  ｉ: "i", ｊ: "j", ｋ: "k", ｌ: "l", ｍ: "m", ｎ: "n", ｏ: "o", ｐ: "p",
  ｑ: "q", ｒ: "r", ｓ: "s", ｔ: "t", ｕ: "u", ｖ: "v", ｗ: "w", ｘ: "x",
  ｙ: "y", ｚ: "z",
  // Latin lookalikes from other blocks
  ı: "i", ĺ: "l", ǃ: "!", ɑ: "a", ɡ: "g", ɩ: "i", ɾ: "r", ʀ: "r",
  Ꭺ: "A", Ᏼ: "B", Ꮯ: "C", Ꭼ: "E", Ꮋ: "H", Ꮶ: "K", Ꮇ: "M", Ꭰ: "D",
};

function normalizeHomoglyphs(text: string): string {
  return [...text].map((c) => HOMOGLYPHS[c] ?? c).join("");
}

// ── Encoding detectors ───────────────────────────────────────────────────────

const BASE64_RE = /[A-Za-z0-9+/]{20,}={0,2}/g;

function tryBase64(text: string): { decoded: string; found: boolean } {
  let found = false;
  const decoded = text.replace(BASE64_RE, (match) => {
    // Must be divisible by 4 (with padding) to be valid base64
    if ((match.length + (match.match(/=/g)?.length ?? 0)) % 4 !== 0 &&
        !match.endsWith("=") && match.length % 4 !== 0) {
      // Try anyway — Buffer.from is lenient
    }
    try {
      const bytes = Buffer.from(match, "base64");
      const str = bytes.toString("utf8");
      // Reject binary garbage — decoded text must be mostly printable
      const printable = str.replace(/[\x20-\x7e\n\r\t]/g, "").length;
      if (printable / str.length > 0.2) return match;
      found = true;
      return str;
    } catch {
      return match;
    }
  });
  return { decoded, found };
}

const URL_ENCODED_RE = /%[0-9a-fA-F]{2}/g;
const HEX_RE = /0x([0-9a-fA-F]{8,})/g;

function tryHexUrl(text: string): { decoded: string; found: boolean } {
  let found = false;

  const urlDecoded = text.replace(URL_ENCODED_RE, (match) => {
    try {
      const decoded = decodeURIComponent(match);
      if (decoded !== match) found = true;
      return decoded;
    } catch {
      return match;
    }
  });

  const hexDecoded = urlDecoded.replace(HEX_RE, (_, hex) => {
    try {
      const bytes = Buffer.from(hex, "hex");
      const str = bytes.toString("utf8");
      const printable = str.replace(/[\x20-\x7e\n\r\t]/g, "").length;
      if (printable / str.length > 0.3) return `0x${hex}`;
      found = true;
      return str;
    } catch {
      return `0x${hex}`;
    }
  });

  return { decoded: hexDecoded, found };
}

const INJECTION_KEYWORDS =
  /ignore|disregard|forget|override|system|prompt|instruction|reveal|bypass|jailbreak|act as|you are now/i;

function rot13char(c: string): string {
  const code = c.charCodeAt(0);
  if (code >= 65 && code <= 90) return String.fromCharCode(((code - 65 + 13) % 26) + 65);
  if (code >= 97 && code <= 122) return String.fromCharCode(((code - 97 + 13) % 26) + 97);
  return c;
}

function tryRot13(text: string): { decoded: string; found: boolean } {
  const rotated = [...text].map(rot13char).join("");
  if (rotated !== text && INJECTION_KEYWORDS.test(rotated) && !INJECTION_KEYWORDS.test(text)) {
    return { decoded: rotated, found: true };
  }
  return { decoded: text, found: false };
}

// ── Main decode function ──────────────────────────────────────────────────────

export function decode(text: string, maxDepth = 3): DecodeResult {
  const decodingApplied: string[] = [];

  // Always strip invisible chars and normalize homoglyphs first, recording each
  // so later stages know the evidence existed before it was normalised away.
  let current = stripInvisibleUnicode(text);
  if (current !== text) decodingApplied.push("invisible_unicode");

  const deglyphed = normalizeHomoglyphs(current);
  if (deglyphed !== current) decodingApplied.push("homoglyph");
  current = deglyphed;

  let depth = 0;

  for (let i = 0; i < maxDepth; i++) {
    const before = current;

    const b64 = tryBase64(current);
    if (b64.found) {
      current = b64.decoded;
      decodingApplied.push("base64");
    }

    const hex = tryHexUrl(current);
    if (hex.found) {
      current = hex.decoded;
      decodingApplied.push("url_encoding/hex");
    }

    const rot = tryRot13(current);
    if (rot.found) {
      current = rot.decoded;
      decodingApplied.push("rot13");
    }

    if (current === before) break;
    depth = i + 1;
  }

  return { text: current, decodingApplied, depth };
}
