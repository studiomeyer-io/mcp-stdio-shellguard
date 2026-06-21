/**
 * `guard_spawn` — defended spawn for streaming use cases. Returns
 * stdout/stderr SHA-256 hashes (not the bodies) so callers that just
 * want fingerprints don't have to keep large buffers.
 */

import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { performance } from "node:perf_hooks";
import { canonicalHash } from "./canonical.js";
import { ShellguardDenied } from "./errors.js";
import { containsUnicodeWhitespace } from "./normalize.js";
import type { ReplayWindow } from "./replay.js";
import type { AllowlistRegistry } from "./allowlist.js";
import { attachSandbox, resolveLimits, type SandboxLimits } from "./sandbox.js";
import { deriveTrustTier, type TrustTier } from "./tier.js";

export interface GuardSpawnInput {
  toolName: string;
  file: string;
  args: string[];
  cwd?: string;
  env?: Record<string, string>;
  fdBudget?: number;
  /**
   * Reject if `shell: true` was passed by mistake. Always rejected —
   * this option exists so callers can opt-in to a clearer error path.
   */
  shell?: boolean;
}

export interface GuardSpawnOutput {
  pid: number | null;
  stdoutHash: string;
  stderrHash: string;
  exitCode: number;
  signal: NodeJS.Signals | null;
  durationMs: number;
  trustTier: TrustTier;
  canonicalHash: string;
  isReplay: boolean;
  fdBudget: number;
}

export interface GuardSpawnDeps {
  registry: AllowlistRegistry;
  replay: ReplayWindow;
  spawnImpl?: typeof spawn;
  now?: () => number;
}

export async function guardSpawn(
  input: GuardSpawnInput,
  deps: GuardSpawnDeps,
): Promise<GuardSpawnOutput> {
  if (input.shell === true) {
    throw new ShellguardDenied(
      "shell:true is forbidden — pass an executable path + args[] vector",
      { toolName: input.toolName },
    );
  }
  if (!input.file || containsUnicodeWhitespace(input.file)) {
    throw new ShellguardDenied(
      "file must be a single executable path, not a shell string",
      { file: input.file },
    );
  }
  if (!Array.isArray(input.args)) {
    throw new ShellguardDenied("args must be a string[] vector", {
      toolName: input.toolName,
    });
  }
  // Defense-in-depth: reject non-string args (see guardExec for the
  // rationale — coercion can slip a non-string past an argsPattern).
  const badArgIndex = input.args.findIndex((a) => typeof a !== "string");
  if (badArgIndex !== -1) {
    throw new ShellguardDenied(
      `args[${badArgIndex}] must be a string, got ${typeof input.args[badArgIndex]}`,
      { toolName: input.toolName, index: badArgIndex },
    );
  }
  const match = deps.registry.match({
    toolName: input.toolName,
    executable: input.file,
    args: input.args,
    ...(input.cwd !== undefined ? { cwd: input.cwd } : {}),
  });
  if (!match.allowed || !match.entry) {
    throw new ShellguardDenied(match.reason ?? "denied", {
      toolName: input.toolName,
    });
  }

  const limits: SandboxLimits = resolveLimits(match.entry.sandboxProfile);
  const effective: SandboxLimits = {
    ...limits,
    fdBudget:
      input.fdBudget !== undefined && input.fdBudget < limits.fdBudget
        ? input.fdBudget
        : limits.fdBudget,
  };

  const hash = canonicalHash({
    executable: input.file,
    args: input.args,
    ...(input.cwd !== undefined ? { cwd: input.cwd } : {}),
    ...(input.env !== undefined ? { env: input.env } : {}),
  });
  const replayResult = deps.replay.record(hash);

  const spawnImpl = deps.spawnImpl ?? spawn;
  const now = deps.now ?? (() => performance.now());
  const start = now();

  const child = spawnImpl(input.file, input.args, {
    cwd: input.cwd,
    env: input.env ?? process.env,
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
  });

  const sandbox = attachSandbox({ child, limits: effective });
  const stdoutHasher = createHash("sha256");
  const stderrHasher = createHash("sha256");
  child.stdout?.on("data", (chunk: Buffer) => stdoutHasher.update(chunk));
  child.stderr?.on("data", (chunk: Buffer) => stderrHasher.update(chunk));

  let exit: { exitCode: number; signal: NodeJS.Signals | null } = {
    exitCode: -1,
    signal: null,
  };
  try {
    const [, , exitInfo] = await Promise.all([
      sandbox.stdoutPromise,
      sandbox.stderrPromise,
      sandbox.exitPromise,
    ]);
    exit = exitInfo;
  } finally {
    sandbox.cleanup();
  }
  const durationMs = now() - start;

  const tier = deriveTrustTier(deps.registry, input.toolName, {
    sandboxActive: true,
    replayActive: true,
  }).tier;

  return {
    pid: child.pid ?? null,
    stdoutHash: stdoutHasher.digest("hex"),
    stderrHash: stderrHasher.digest("hex"),
    exitCode: exit.exitCode,
    signal: exit.signal,
    durationMs,
    trustTier: tier,
    canonicalHash: hash,
    isReplay: replayResult.isReplay,
    fdBudget: effective.fdBudget,
  };
}
