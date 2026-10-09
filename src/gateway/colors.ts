/**
 * Pure ANSI color helpers for rich stderr logging.
 *
 * Colors auto-disable when stderr is not a TTY or NO_COLOR is set, following
 * the NO_COLOR convention (https://no-color.org/).
 *
 * Zero npm dependencies — only ANSI escape codes.
 */

const enabled = !!(process.stderr?.isTTY && !process.env.NO_COLOR);

/** Wrap string in ANSI red (errors, blocks). */
export const red = (s: string): string => (enabled ? `\x1b[31m${s}\x1b[0m` : s);

/** Wrap string in ANSI green (allows, clean). */
export const green = (s: string): string => (enabled ? `\x1b[32m${s}\x1b[0m` : s);

/** Wrap string in ANSI yellow (warnings, spotlight). */
export const yellow = (s: string): string => (enabled ? `\x1b[33m${s}\x1b[0m` : s);

/** Wrap string in ANSI cyan (URLs, info). */
export const cyan = (s: string): string => (enabled ? `\x1b[36m${s}\x1b[0m` : s);

/** Wrap string in ANSI bold. */
export const bold = (s: string): string => (enabled ? `\x1b[1m${s}\x1b[0m` : s);

/** Wrap string in ANSI dim (secondary info). */
export const dim = (s: string): string => (enabled ? `\x1b[2m${s}\x1b[0m` : s);

/** A horizontal rule line using box-drawing heavy horizontal (U+2501), 60 chars wide. */
export const rule = (): string => "━".repeat(60);

/** Unicode emoji — always render regardless of TTY since they are not ANSI. */
export const emoji = {
  shield: "🛡",
  check: "✅",
  block: "🚫",
  warn: "⚠️",
  spark: "✨",
} as const;
