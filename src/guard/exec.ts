/**
 * `guard_exec` — drop-in defended replacement for child_process.exec.
 *
 * Forces an args[] vector, rejects shell:true, applies allowlist match,
 * runs through the sandbox + replay window. Returns a structured
 * result that callers can serialise as MCP tool output.
 */

import { spawn } from "node:child_process";
import { performance } from "node:perf_hooks";
import { canonicalHash } from "./canonical.js";
import { ShellguardDenied } from "./errors.js";
import { containsUnicodeWhitespace } from "./normalize.js";
import type { ReplayWindow } from "./replay.js";
import type { AllowlistRegistry } from "./allowlist.js";
import { attachSandbox, resolveLimits, type SandboxLimits } from "./sandbox.js";
import { deriveTrustTier, type TrustTier } from "./tier.js";

export interface GuardExecInput {
  toolName: string;
  command: string;
  args: string[];
  cwd?: string;
  env?: Record<string, string>;
  /**
   * Override the sandbox timeout for this single invocation. Must be
   * <= the profile timeout — caller cannot widen the limit.
   */
  timeoutMs?: number;
  /**
   * Hard-fail if the canonical hash is already in the replay window.
   * Default false — replay is reported in the result, not enforced.
   */
  blockOnReplay?: boolean;
}

export interface GuardExecOutput {
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
  trustTier: TrustTier;
  canonicalHash: string;
  isReplay: boolean;
  signal: NodeJS.Signals | null;
}

export interface GuardExecDeps {
  registry: AllowlistRegistry;
  replay: ReplayWindow;
  /** Test seam — defaults to node:child_process.spawn. */
  spawnImpl?: typeof spawn;
  /** Test seam for performance timing. */
  now?: () => number;
}

export async function guardExec(
  input: GuardExecInput,
  deps: GuardExecDeps,
): Promise<GuardExecOutput> {
  if (!input.command || containsUnicodeWhitespace(input.command)) {
    throw new ShellguardDenied(
      "command must be a single executable path, not a shell string",
      { command: input.command },
    );
  }
  if (!Array.isArray(input.args)) {
    throw new ShellguardDenied("args must be a string[] vector", {
      toolName: input.toolName,
    });
  }

  const match = deps.registry.match({
    toolName: input.toolName,
    executable: input.command,
    args: input.args,
    ...(input.cwd !== undefined ? { cwd: input.cwd } : {}),
  });
  if (!match.allowed || !match.entry) {
    throw new ShellguardDenied(match.reason ?? "denied", {
      toolName: input.toolName,
    });
  }

  const limits: SandboxLimits = resolveLimits(match.entry.sandboxProfile);
  const effectiveLimits: SandboxLimits = {
    ...limits,
    timeoutMs:
      input.timeoutMs !== undefined && input.timeoutMs < limits.timeoutMs
        ? input.timeoutMs
        : limits.timeoutMs,
  };

  const hash = canonicalHash({
    executable: input.command,
    args: input.args,
    ...(input.cwd !== undefined ? { cwd: input.cwd } : {}),
    ...(input.env !== undefined ? { env: input.env } : {}),
  });
  const replayResult = deps.replay.record(hash);
  if (input.blockOnReplay && replayResult.isReplay) {
    throw new ShellguardDenied("replay blocked by caller policy", {
      toolName: input.toolName,
      canonicalHash: hash,
    });
  }

  const spawnImpl = deps.spawnImpl ?? spawn;
  const now = deps.now ?? (() => performance.now());
  const start = now();

  const child = spawnImpl(input.command, input.args, {
    cwd: input.cwd,
    env: input.env ?? process.env,
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
  });

  const sandbox = attachSandbox({ child, limits: effectiveLimits });
  let stdoutBuf: Buffer = Buffer.alloc(0);
  let stderrBuf: Buffer = Buffer.alloc(0);
  let exit: { exitCode: number; signal: NodeJS.Signals | null } = {
    exitCode: -1,
    signal: null,
  };
  try {
    const [stdout, stderr, exitInfo] = await Promise.all([
      sandbox.stdoutPromise,
      sandbox.stderrPromise,
      sandbox.exitPromise,
    ]);
    stdoutBuf = stdout;
    stderrBuf = stderr;
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
    stdout: stdoutBuf.toString("utf8"),
    stderr: stderrBuf.toString("utf8"),
    exitCode: exit.exitCode,
    durationMs,
    trustTier: tier,
    canonicalHash: hash,
    isReplay: replayResult.isReplay,
    signal: exit.signal,
  };
}
