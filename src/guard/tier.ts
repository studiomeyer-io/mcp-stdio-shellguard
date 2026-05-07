/**
 * Trust-tier derivation per registered tool.
 *
 * - LOW    : tool not registered → default-deny applies, cannot run
 * - MEDIUM : executable whitelisted but args wide open
 * - HIGH   : executable + args regex constrained
 * - CRITICAL: HIGH + active sandbox + active replay window
 */

import type { AllowlistRegistry } from "./allowlist.js";

export type TrustTier = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface TrustTierDescriptor {
  tier: TrustTier;
  reasons: string[];
  improvementHints: string[];
}

export interface TrustTierContext {
  /** Is the process sandbox active for this tool's invocations? */
  sandboxActive: boolean;
  /** Is the replay window active and recording? */
  replayActive: boolean;
}

export function deriveTrustTier(
  registry: AllowlistRegistry,
  toolName: string,
  ctx: TrustTierContext,
): TrustTierDescriptor {
  const entry = registry.get(toolName);
  if (!entry) {
    return {
      tier: "LOW",
      reasons: [`tool '${toolName}' not registered`],
      improvementHints: [
        "call register_allowlist({ toolName, executable, argsPatterns }) " +
          "to lift the default-deny",
      ],
    };
  }
  if (entry.argsRegex.length === 0) {
    return {
      tier: "MEDIUM",
      reasons: [
        `executable '${entry.executable}' whitelisted but no argsPattern set`,
      ],
      improvementHints: [
        "add argsPatterns regexes to constrain the args[] vector",
        "add cwdPattern if the tool only operates in a fixed dir",
      ],
    };
  }
  if (!ctx.sandboxActive || !ctx.replayActive) {
    const missing: string[] = [];
    if (!ctx.sandboxActive) missing.push("sandbox");
    if (!ctx.replayActive) missing.push("replay");
    return {
      tier: "HIGH",
      reasons: [
        `executable + ${entry.argsRegex.length} argsPatterns enforced`,
      ],
      improvementHints: missing.map(
        (m) => `enable ${m} (set sandboxProfile and call replay_check)`,
      ),
    };
  }
  return {
    tier: "CRITICAL",
    reasons: [
      "executable + args regex enforced",
      "sandbox active",
      "replay window active",
    ],
    improvementHints: [],
  };
}
