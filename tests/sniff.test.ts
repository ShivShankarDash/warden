import { describe, expect, test } from "bun:test";
import { sniff, formatMismatch, isUnscannable } from "../src/extract/sniff.ts";

const bytes = async (p: string) => new Uint8Array(await Bun.file(p).arrayBuffer());

describe("sniff — binary formats", () => {
  test("identifies a real PDF by magic bytes", async () => {
    expect(sniff(await bytes("test-fixtures/binary/pdf-white-text.pdf"))).toBe("pdf");
  });
  test("identifies a real DOCX inside the zip container", async () => {
    expect(sniff(await bytes("test-fixtures/binary/docx-hidden.docx"))).toBe("docx");
  });
  test("bytes that are not a known binary fall through to text handling", () => {
    expect(sniff(new TextEncoder().encode("just some prose here"))).toBe("text");
  });
});

describe("sniff — text formats", () => {
  test("html", () => {
    expect(sniff("<!DOCTYPE html><html><body><p>hi</p></body></html>")).toBe("html");
    expect(sniff("<div><span>a</span><p>b</p></div>")).toBe("html");
  });
  test("json", () => {
    expect(sniff('{"a":1,"b":[2,3]}')).toBe("api_json");
    expect(sniff("[1,2,3]")).toBe("api_json");
  });
  test("malformed json is not json", () => {
    expect(sniff("{not valid json at all")).not.toBe("api_json");
  });
  test("email headers", () => {
    expect(sniff("From: a@b.com\nTo: c@d.com\nSubject: Hi\n\nBody text.")).toBe("email");
  });
  test("markdown needs more than one signal", () => {
    expect(sniff("# Title\n\n- item one\n- item two\n\n[link](https://x.com)")).toBe("markdown");
    expect(sniff("Just a sentence with a - dash in it.")).toBe("text");
  });
  test("plain prose", () => {
    expect(sniff("The quarterly figures are attached for your review.")).toBe("text");
  });
});

describe("formatMismatch", () => {
  test("flags content that cannot be the declared format", () => {
    expect(formatMismatch("pdf", "html")).toBe(true);
    expect(formatMismatch("api_json", "html")).toBe(true);
  });
  test("accepts matching declarations", () => {
    expect(formatMismatch("html", "html")).toBe(false);
    expect(formatMismatch("pdf", "pdf")).toBe(false);
  });
  test("provenance labels make no format claim", () => {
    // Sniffing cannot tell whether a human typed this, so it must not object.
    expect(formatMismatch("user_message", "html")).toBe(false);
    expect(formatMismatch("mcp_tool_description", "api_json")).toBe(false);
    expect(formatMismatch("a2a_message", "api_json")).toBe(false);
  });
  test("containers may legitimately hold other formats", () => {
    expect(formatMismatch("email", "html")).toBe(false);
    expect(formatMismatch("markdown", "html")).toBe(false);
  });
  test("unidentifiable content is never a mismatch", () => {
    expect(formatMismatch("pdf", "text")).toBe(false);
  });
});

describe("sniff — binary detection", () => {
  const withSig = (sig: number[]) =>
    new Uint8Array([...sig, ...Array.from({ length: 512 }, (_, i) => (i * 2654435761) % 256)]);

  test("recognises image formats by magic bytes", () => {
    expect(sniff(withSig([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))).toBe("image"); // PNG
    expect(sniff(withSig([0xff, 0xd8, 0xff]))).toBe("image");                                // JPEG
    expect(sniff(withSig([0x47, 0x49, 0x46, 0x38]))).toBe("image");                          // GIF
  });

  test("recognises archives and executables as unscannable binary", () => {
    expect(sniff(withSig([0x1f, 0x8b]))).toBe("binary");                   // gzip
    expect(sniff(withSig([0x7f, 0x45, 0x4c, 0x46]))).toBe("binary");       // ELF
    expect(sniff(withSig([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]))).toBe("binary"); // 7z
  });

  test("catches unsigned binary by control-character density", () => {
    const noise = new Uint8Array(Array.from({ length: 512 }, (_, i) => (i % 7 === 0 ? 0 : i % 256)));
    expect(sniff(noise)).toBe("binary");
  });

  test("does not mistake ordinary text bytes for binary", () => {
    const text = new TextEncoder().encode(
      "Dear team,\n\nPlease review the attached figures before Friday.\n\nRegards"
    );
    expect(sniff(text)).not.toBe("binary");
  });

  test("real fixtures are still identified, not swallowed as binary", async () => {
    expect(sniff(await bytes("test-fixtures/binary/pdf-white-text.pdf"))).toBe("pdf");
    expect(sniff(await bytes("test-fixtures/binary/docx-hidden.docx"))).toBe("docx");
  });

  test("binary contradicts a text declaration, including provenance labels", () => {
    // A "user_message" that is actually a gzip stream is wrong however it arrived.
    expect(formatMismatch("user_message", "binary")).toBe(true);
    expect(formatMismatch("email", "binary")).toBe(true);
    expect(formatMismatch("image", "binary")).toBe(false);
  });

  test("isUnscannable marks binary but not images", () => {
    expect(isUnscannable("binary")).toBe(true);
    expect(isUnscannable("image")).toBe(false); // OCR may still find text
    expect(isUnscannable("text")).toBe(false);
  });
});

describe("sniff — improved text heuristics", () => {
  test("a small HTML injection is detected despite few tags", () => {
    expect(sniff(`Results found.<div style="display:none">payload</div>`)).toBe("html");
  });

  test("an HTML comment alone is enough", () => {
    expect(sniff(`Some text <!-- hidden instruction --> more text`)).toBe("html");
  });

  test("a single decisive markdown construct is enough", () => {
    expect(sniff("# Notes\n\n[t]: https://x.com/c?data=AAAA")).toBe("markdown");
    expect(sniff("Intro\n\n```js\nconst x = 1;\n```")).toBe("markdown");
  });

  test("prose with one weak signal is still text", () => {
    expect(sniff("Just a sentence with a - dash in it.")).toBe("text");
  });
});
