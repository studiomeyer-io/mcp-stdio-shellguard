/**
 * Public API for `mcp-stdio-shellguard`.
 *
 * Library callers import from here. The reference MCP server lives in
 * ./server.ts and is also a `bin` entry-point. The audit CLI lives in
 * ./cli.ts.
 */

export {
  ShellguardError,
  ShellguardDenied,
  ShellguardTimeout,
  ShellguardLimitExceeded,
} from "./guard/errors.js";
export type { ShellguardErrorCode } from "./guard/errors.js";

export { canonicalize, canonicalHash, SEMANTIC_ENV_KEYS } from "./guard/canonical.js";
export type { CanonicalInput } from "./guard/canonical.js";

export {
  normalizeForMatching,
  containsUnicodeWhitespace,
  UNICODE_WHITESPACE_RE,
} from "./guard/normalize.js";

export { ReplayWindow } from "./guard/replay.js";
export type {
  ReplayEntry,
  ReplayCheckResult,
  ReplayWindowOptions,
} from "./guard/replay.js";

export { AllowlistRegistry } from "./guard/allowlist.js";
export type {
  SandboxProfile,
  AllowlistEntry,
  AllowlistEntryInput,
  AllowlistMatchInput,
  AllowlistMatchResult,
} from "./guard/allowlist.js";

export {
  SANDBOX_PROFILES,
  attachSandbox,
  probeCgroupV2,
  resolveLimits,
} from "./guard/sandbox.js";
export type {
  SandboxLimits,
  SandboxStatus,
  CgroupProbeResult,
  SandboxAttachOptions,
  SandboxAttachResult,
} from "./guard/sandbox.js";

export { deriveTrustTier } from "./guard/tier.js";
export type {
  TrustTier,
  TrustTierDescriptor,
  TrustTierContext,
} from "./guard/tier.js";

export { guardExec } from "./guard/exec.js";
export type {
  GuardExecInput,
  GuardExecOutput,
  GuardExecDeps,
} from "./guard/exec.js";

export { guardSpawn } from "./guard/spawn.js";
export type {
  GuardSpawnInput,
  GuardSpawnOutput,
  GuardSpawnDeps,
} from "./guard/spawn.js";

export {
  PATTERN_RULES,
  SEVERITY_RANK,
  evaluateCall,
  severityAtOrAbove,
} from "./audit/patterns.js";
export type {
  AuditSeverity,
  AuditFinding,
  PatternMatch,
  PatternRule,
} from "./audit/patterns.js";

export { scanPath, relativiseFindings } from "./audit/scanner.js";
export type { AuditScanOptions, AuditScanResult } from "./audit/scanner.js";

export { renderReport } from "./audit/report.js";
export type { ReportFormat, RenderedReport } from "./audit/report.js";

export { SUGGESTED_FIX } from "./audit/suggested-fix.js";
export type { AuditPatternId } from "./audit/suggested-fix.js";
