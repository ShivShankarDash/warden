# Spec 02: Extract — What "Hidden" Means Per Source

## What is this piece?
Extractors take raw content in any format and return two text streams: `visibleText` (what a normal reader would see) and `hiddenText` (what an attacker hid that a normal reader would miss), plus a provenance record of where each hidden section came from.

## Input → Output
**Input:** raw content (`string` or `Uint8Array`) and a `SourceType`.

**Output:**
```ts
{
  visibleText: string;          // what a normal reader sees
  hiddenText: string;           // concatenated hidden sections
  provenance: {
    source: SourceType;
    hiddenSections: { type: string; content: string }[];
  };
}
```

## How it works
1. The dispatcher in `src/extract/index.ts` routes to the correct extractor based on `source`.
2. Each extractor parses the content with its library (cheerio, mailparser, etc.).
3. The extractor separates visible from hidden text using the per-source rules below.
4. Both streams are returned. The orchestrator concatenates them (hidden appended after visible) before passing to the decoder and detectors.
5. Provenance records the type and content of each hidden section — this is used in findings to say "found in HTML comment" or "found in invisible PDF layer."

## Tricky cases
- **White text on white background:** CSS color `#fff`, `rgb(255,255,255)`, or `color: white` on a white `background-color` — requires checking both the element's color *and* its computed background. For now, flag any element with `color: white` or `color: #fff` or `color: #ffffff` regardless of background.
- **Tiny font injections:** `font-size: 0`, `font-size: 0.1px`, `font-size: 1px` — flag any element with font-size ≤ 1px.
- **EchoLeak markdown trick:** a reference-style image `![alt][ref]` where `ref` resolves to a URL with a title attribute. The title is invisible in most renderers but is sent in the HTTP request when the image loads — this is the actual exfiltration channel. Flag all image titles and reference-style link/image titles as hidden.
- **DOCX tracked deletions:** deleted text in tracked changes is still in the XML (`<w:del>` elements). An attacker can write an instruction, then "delete" it — the AI reading the DOCX via mammoth won't see it, but it's in the file. Extract `<w:del>` text as hidden.
- **PDF metadata:** the `/Info` dictionary (Title, Author, Subject, Keywords) and `/Metadata` XMP stream are never rendered but are parsed by some AI pipelines. Extract as hidden.

## How I'll test it
- For each source, at least 3 eval cases with content that has a hidden injection — the extractor must put the injection in `hiddenText`, not `visibleText`.
- A benign HTML page with `display:none` for purely decorative reasons (e.g. a mobile/desktop toggle) must not produce a false-positive finding — the hidden *text content* triggers, not the presence of `display:none` alone.
- Test with an empty file and a malformed file per binary source — must not throw, must return empty strings.

## Not doing
- CSS `opacity: 0` detection (requires a full CSS engine to compute; too complex for now).
- Detecting injections in PDF form field values (out of scope for initial version).
- Following `<iframe>` or `<link>` to fetch external content (network calls in the extractor are out of scope).

## Open questions
- Should `visibleText` and `hiddenText` be scanned with different weights by the detector, or just concatenated? Current plan: concatenate for detection, but tag each finding's span with its provenance so the dashboard shows "found in hidden HTML comment."

---

## Hidden-content definition per source

### html
| Type | Rule |
|---|---|
| hidden element | `display: none` or `visibility: hidden` in inline style or a `<style>` tag |
| white text | `color: #fff`, `color: white`, `color: #ffffff`, `color: rgb(255,255,255)` |
| tiny font | `font-size` ≤ 1px or `font-size: 0` |
| HTML comment | `<!-- any content here -->` |
| image alt text | `alt` attribute on `<img>` tags |
| aria labels | `aria-label`, `aria-description` attributes |
| meta content | `<meta name="..." content="...">` — all content values |
| noscript | `<noscript>` body |

### email
| Type | Rule |
|---|---|
| HTML body hidden | Same rules as HTML above applied to the HTML email body |
| suspicious headers | Any non-standard `X-` headers and the `Subject` field |
| attachment names | Filenames of all attachments (the actual attachment content is a separate scan) |

### pdf
| Type | Rule |
|---|---|
| invisible text | Text with color set to white or opacity 0 (detected via PDF operator stream) |
| metadata | All fields from the `/Info` dictionary |
| XMP metadata | Content of the `/Metadata` XMP stream |
| extra text layers | Text objects outside the visible page bounds (coordinates < 0 or > page size) |

### docx
| Type | Rule |
|---|---|
| hidden runs | `<w:rPr><w:vanish/></w:rPr>` — text marked as hidden in Word |
| comments | `<w:comment>` elements from `word/comments.xml` |
| tracked deletions | `<w:del>` elements — deleted text still present in XML |
| revision insertions | `<w:ins>` from tracked changes — accepted insertions that haven't been cleaned |

### markdown
| Type | Rule |
|---|---|
| link titles | `[text](url "TITLE")` — the quoted title string |
| image alt | `![ALT TEXT](url)` — the alt text |
| image titles | `![alt](url "TITLE")` — the quoted title |
| HTML comments | `<!-- comment -->` embedded in markdown |
| reference-style titles | `[ref]: url "TITLE"` — title in reference definitions (EchoLeak vector) |

### api_json
No hidden/visible split — all string values are equally suspicious. The entire extracted text is `visibleText`; `hiddenText` is empty. The JSON walker recursively extracts all string values regardless of key name.

### code
| Type | Rule |
|---|---|
| line comments | `//`, `#`, `--`, `%` prefixed lines |
| block comments | `/* ... */` |
| docstrings | `"""..."""` or `'''...'''` in Python |
| string literals | All quoted string values |
The actual code tokens (keywords, identifiers) are `visibleText`; comments and string literals are `hiddenText`.

### image / ocr_text
All text extracted by Tesseract OCR is treated as `hiddenText` — it was invisible in the raw bytes and only becomes visible after OCR. `visibleText` is empty. For `ocr_text` source (pre-extracted), everything is `visibleText`.

### mcp_tool_description
No hidden/visible split — the full description text is `visibleText`. Any injection in an MCP tool description is in plain sight by design (the attack relies on the AI trusting tool metadata).

### a2a_message
Same as `mcp_tool_description` — full content is `visibleText`. No structural hiding.

## Provenance contract
- The order of `hiddenSections` follows document order (top-to-bottom, depth-first for nested HTML).
- The visible/hidden split is preserved all the way to findings: each `Finding.spans` offset is relative to the full concatenated text (`visibleText + "\n" + hiddenText`), with the boundary offset recorded so the dashboard can annotate "this span was in a hidden HTML comment."
- Detectors scan the full concatenated text but findings that originate in `hiddenText` are weighted more heavily in the risk score (hidden injection is more suspicious than visible injection).
