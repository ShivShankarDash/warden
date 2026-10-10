/**
 * Strings whose dotted tokens and 40-character blobs must NOT be redacted.
 *
 * PII redaction rewrites the content that is then handed to the model, so an
 * over-matching pattern silently corrupts ordinary messages — the model reads
 * "[REDACTED_HOSTNAME]" where the user wrote "example.co.uk" and answers the
 * wrong question. Both new patterns (hostname, aws_secret) key on shapes that
 * collide with everyday text, so these are the collisions, written out.
 */
export const BENIGN_DOTTED: string[] = [
  "Upgrade to version 1.2.3 before running the migration.",
  "See acme.com for the pricing page.",
  "Extract it with tar -xzf file.tar.gz and then run the installer.",
  "Node.js 20 is required; earlier releases fail on the crypto import.",
  "Our UK entity is registered at example.co.uk under the same group.",
  "The invoice was issued by the supplier at acme.",
  "Rename settings.local.json to settings.json before deploying.",
  "The bundler config lives in webpack.config.local.js at the repo root.",
  "The class is com.acme.internal.utils.StringHelper, not the public one.",
  "That lives in the internal.api.handler module, which we're deprecating.",
  "Read blog.dev.to for the write-up on the migration.",
  "The docs are at https://docs.example.com/guide/getting-started today.",
  "Check local.gov.uk for the council's planning rules.",
  "The file is named report.final.v2.pdf in the shared drive.",
  "Use the corp.pricing sheet in the finance workbook, tab 3.",
  "Python's os.path.join is what you want here, not string concatenation.",
  "The test asserts response.data.items.length is 3.",
  "Compare it with staging.acme.com, which has the old theme.",
];

export const BENIGN_BLOBS: string[] = [
  "The regression landed in commit 0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b last week.",
  // The AKIA id here is a real detection (aws_key) and is meant to fire; the
  // commit hash beside it is the part that must survive, since an access key id
  // in the text is exactly what makes a nearby blob look like its secret.
  "Our key AKIAIOSFODNN7EXAMPLE was rotated in commit 0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b.",
  "The build id is cGFja2FnZUJ1aWxkMjAyNDExMDdSZWxlYXNlQnVpbGRYWVo and it changes nightly.",
  "Integrity hash sha1-L1eXLrpStOmTxNGmLfhPIDO8MQhY7lGP for the vendored bundle.",
  "The nonce was MFowDQYJKoZIhvcNAQEBBQADSQAwRgJBAKj34GZxWgo and the request still failed.",
  "The cache key SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvcmxkSGVsbG8 is derived from the inputs.",
  "The secret is stored in the vault, not in the repository.",
  "Rotate the secret access key quarterly; the runbook explains how.",
  "This content hash 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 identifies the blob.",
];
