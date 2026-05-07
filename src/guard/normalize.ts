/**
 * Unicode normalisation helpers for the guard layer.
 *
 * Defends against three bypass classes the cold-cross-review (S991-Folge,
 * mcp-armor S988 precedent) flagged before v0.1.0 promotion:
 *
 * 1. Allowlist-Regex bypass via Fullwidth chars (U+FF01..U+FF5E). An
 *    attacker who controls tool args can write fullwidth `log` and slip
 *    past `^log$` because the regex sees a different codepoint sequence.
 *    NFKC compatibility-decomposition collapses fullwidth chars back to
 *    ASCII so the regex catches them.
 *
 * 2. Replay-Window bypass via zero-width chars (U+200B..U+200D, U+FEFF,
 *    line/paragraph separators U+2028/U+2029, bidi formatting
 *    U+202A..U+202E and U+2066..U+2069). An attacker who knows the replay
 *    TTL can append a random ZWC to an arg to generate a different
 *    canonical hash on each call, silently defeating replay detection.
 *    Stripping these characters before hashing closes the gap.
 *
 * 3. Whitespace-check bypass via non-ASCII whitespace (U+00A0 NBSP,
 *    U+1680 OGHAM, U+2000..U+200A, U+202F, U+205F, U+3000 IDEOGRAPHIC,
 *    U+FEFF). The bare `command.includes(" ")` check in exec/spawn was
 *    ASCII-only and gave false confidence that the input was a single
 *    executable path.
 *
 * The regex sources are built via `new RegExp(<source-string>)` rather
 * than literal `/.../`. This avoids the TypeScript regex-literal parser
 * trap where U+2028 (LINE SEPARATOR) inside a literal terminates the
 * regex token early. Pattern follows mcp-armor S991 precedent.
 */

/**
 * Codepoints stripped BEFORE matching/hashing. No semantic value in a
 * shell-argument context — they exist purely to bypass naive matchers.
 */
const STRIPPABLE_CODEPOINTS_SOURCE =
  "[\\u200B-\\u200D\\uFEFF\\u2028\\u2029\\u202A-\\u202E\\u2066-\\u2069\\u2061-\\u2064]";
const STRIPPABLE_CODEPOINTS_RE = new RegExp(STRIPPABLE_CODEPOINTS_SOURCE, "g");

/**
 * Codepoints any tool should reject in a "single executable path"
 * position. ASCII whitespace + the Unicode whitespace blocks an
 * attacker could use to smuggle a multi-token command.
 */
const UNICODE_WHITESPACE_SOURCE =
  "[\\s\\u00A0\\u1680\\u2000-\\u200A\\u202F\\u205F\\u3000\\uFEFF]";
export const UNICODE_WHITESPACE_RE = new RegExp(UNICODE_WHITESPACE_SOURCE);

/**
 * Apply NFKC compatibility-normalisation and strip bypass codepoints.
 * Used by:
 * - `AllowlistRegistry.match` before `argsRegex.test(arg)` so an
 *   attacker cannot smuggle past `^log$` with `log` + a zero-width joiner.
 * - `canonicalize` so two commands that differ only by zero-width
 *   chars produce the same SHA-256 hash and the replay window catches
 *   the second call.
 *
 * `normalize("NFKC")` is idempotent, deterministic, and well-defined
 * for arbitrary UTF-16. Empty string in → empty string out. Non-string
 * inputs pass through unchanged so callers do not have to type-guard.
 */
export function normalizeForMatching<T>(s: T): T {
  if (typeof s !== "string" || s.length === 0) return s;
  return (s as string)
    .normalize("NFKC")
    .replace(STRIPPABLE_CODEPOINTS_RE, "") as T;
}

/**
 * True when the string contains any character that would be ambiguous
 * in a "single executable path" position. The exec/spawn guards reject
 * the input outright in this case rather than try to repair it.
 */
export function containsUnicodeWhitespace(s: string): boolean {
  if (typeof s !== "string" || s.length === 0) return false;
  return UNICODE_WHITESPACE_RE.test(s);
}
