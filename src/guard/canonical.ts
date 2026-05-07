/**
 * Canonicalisation for replay detection.
 *
 * Hashes (executable, args[], cwd, envSubset) into a stable SHA-256
 * string. Only a small whitelist of env vars is included so that
 * benign variation (PWD, SHLVL, terminal info) does not break the
 * replay match.
 *
 * All string components are normalised via NFKC + bypass-codepoint
 * strip BEFORE hashing so an attacker cannot defeat replay detection
 * by appending a zero-width joiner to an arg on each call. See
 * `./normalize.ts` for the full character set.
 */

import { createHash } from "node:crypto";
import { normalizeForMatching } from "./normalize.js";

/**
 * Env vars that meaningfully change command semantics. Anything else
 * is dropped from the canonical hash so two calls that only differ in
 * `TERM` or `PWD` collide as expected.
 */
const SEMANTIC_ENV_KEYS: readonly string[] = [
  "PATH",
  "LANG",
  "LC_ALL",
  "TZ",
  "HOME",
  "USER",
  "NODE_ENV",
];

export interface CanonicalInput {
  executable: string;
  args: readonly string[];
  cwd?: string | undefined;
  env?: Record<string, string | undefined> | undefined;
  /**
   * Override which env keys to include. Defaults to SEMANTIC_ENV_KEYS.
   */
  envKeys?: readonly string[];
}

/**
 * Build the canonical string for a command invocation. Deterministic
 * across calls with semantically identical inputs.
 */
export function canonicalize(input: CanonicalInput): string {
  const envKeys = input.envKeys ?? SEMANTIC_ENV_KEYS;
  const envSubset: Array<[string, string]> = [];
  if (input.env) {
    for (const key of envKeys) {
      const value = input.env[key];
      if (value !== undefined) {
        envSubset.push([key, normalizeForMatching(value)]);
      }
    }
    envSubset.sort(([a], [b]) => a.localeCompare(b));
  }

  return JSON.stringify({
    executable: normalizeForMatching(input.executable),
    args: input.args.map((a) => normalizeForMatching(a)),
    cwd: input.cwd === undefined ? null : normalizeForMatching(input.cwd),
    env: envSubset,
  });
}

export function canonicalHash(input: CanonicalInput): string {
  const canonical = canonicalize(input);
  return createHash("sha256").update(canonical).digest("hex");
}

export { SEMANTIC_ENV_KEYS };
