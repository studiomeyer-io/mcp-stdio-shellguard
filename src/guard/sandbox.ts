/**
 * Process sandbox helpers: timeout, byte caps, fd budget, optional
 * cgroup-v2. The sandbox returns an `applyTo` callable that wraps a
 * spawned child process with kill-on-overflow guards.
 */

import { promises as fs } from "node:fs";
import type { ChildProcess } from "node:child_process";
import type { SandboxProfile } from "./allowlist.js";
import { ShellguardLimitExceeded, ShellguardTimeout } from "./errors.js";

export interface SandboxLimits {
  timeoutMs: number;
  maxStdoutBytes: number;
  maxStderrBytes: number;
  fdBudget: number;
  /** cgroup limits applied if cgroup-v2 is detected and writable. */
  cgroup?: {
    memoryMaxBytes: number;
    cpuMaxQuota: number;
  };
}

export const SANDBOX_PROFILES: Record<SandboxProfile, SandboxLimits> = {
  strict: {
    timeoutMs: 5_000,
    maxStdoutBytes: 1 * 1024 * 1024,
    maxStderrBytes: 1 * 1024 * 1024,
    fdBudget: 32,
    cgroup: {
      memoryMaxBytes: 128 * 1024 * 1024,
      cpuMaxQuota: 20_000,
    },
  },
  standard: {
    timeoutMs: 30_000,
    maxStdoutBytes: 10 * 1024 * 1024,
    maxStderrBytes: 10 * 1024 * 1024,
    fdBudget: 256,
    cgroup: {
      memoryMaxBytes: 512 * 1024 * 1024,
      cpuMaxQuota: 50_000,
    },
  },
  permissive: {
    timeoutMs: 5 * 60_000,
    maxStdoutBytes: 100 * 1024 * 1024,
    maxStderrBytes: 100 * 1024 * 1024,
    fdBudget: 1024,
  },
};

export interface SandboxStatus {
  profile: SandboxProfile;
  timeoutMs: number;
  maxStdoutBytes: number;
  maxStderrBytes: number;
  fdBudget: number;
  cgroupActive: boolean;
  cgroupLimits?: { memoryMaxBytes: number; cpuMaxQuota: number };
}

export interface CgroupProbeResult {
  active: boolean;
  reason?: string;
}

/**
 * Detect whether cgroup-v2 is mounted writable for non-root sub-folders.
 * Pure read-only access — never writes here. Caller decides whether to
 * actually create a cgroup.
 */
export async function probeCgroupV2(
  cgroupRoot = "/sys/fs/cgroup",
  fsApi: { access: typeof fs.access } = fs,
): Promise<CgroupProbeResult> {
  try {
    await fsApi.access(`${cgroupRoot}/cgroup.controllers`, fs.constants.R_OK);
  } catch (err) {
    return {
      active: false,
      reason: `cgroup-v2 not mounted at ${cgroupRoot}: ${(err as Error).message}`,
    };
  }
  try {
    await fsApi.access(cgroupRoot, fs.constants.W_OK);
  } catch {
    return {
      active: false,
      reason: `${cgroupRoot} not writable (need root or delegated subtree)`,
    };
  }
  return { active: true };
}

/**
 * Resolve a profile name to concrete limits.
 */
export function resolveLimits(profile: SandboxProfile): SandboxLimits {
  return SANDBOX_PROFILES[profile];
}

export interface SandboxAttachOptions {
  child: ChildProcess;
  limits: SandboxLimits;
  /** Called with the bytes captured so far on stdout. */
  onStdoutChunk?: (totalBytes: number) => void;
  onStderrChunk?: (totalBytes: number) => void;
}

export interface SandboxAttachResult {
  stdoutPromise: Promise<Buffer>;
  stderrPromise: Promise<Buffer>;
  /** Resolves when the process has exited cleanly within limits. */
  exitPromise: Promise<{ exitCode: number; signal: NodeJS.Signals | null }>;
  /** Cancel the timeout / abort handlers. Always call in a finally. */
  cleanup: () => void;
}

/**
 * Attach overflow + timeout guards to an already-spawned child. The
 * child is killed (SIGKILL after SIGTERM grace) if any limit is hit.
 */
export function attachSandbox(opts: SandboxAttachOptions): SandboxAttachResult {
  const { child, limits } = opts;
  const stdoutChunks: Buffer[] = [];
  const stderrChunks: Buffer[] = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let timedOut = false;
  let stdoutOverflowed = false;
  let stderrOverflowed = false;

  const killChild = (signal: NodeJS.Signals): void => {
    if (!child.killed) {
      try {
        child.kill(signal);
      } catch {
        // already exited — ignore
      }
    }
  };

  const timer = setTimeout(() => {
    timedOut = true;
    killChild("SIGTERM");
    setTimeout(() => killChild("SIGKILL"), 500).unref();
  }, limits.timeoutMs);
  timer.unref();

  const stdoutPromise = new Promise<Buffer>((resolve, reject) => {
    const stream = child.stdout;
    if (!stream) {
      resolve(Buffer.alloc(0));
      return;
    }
    stream.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > limits.maxStdoutBytes) {
        stdoutOverflowed = true;
        killChild("SIGTERM");
        reject(
          new ShellguardLimitExceeded(
            "SHELLGUARD_STDOUT_LIMIT",
            `stdout exceeded ${limits.maxStdoutBytes} bytes`,
            { bytes: stdoutBytes, limit: limits.maxStdoutBytes },
          ),
        );
        return;
      }
      stdoutChunks.push(chunk);
      opts.onStdoutChunk?.(stdoutBytes);
    });
    stream.on("end", () => resolve(Buffer.concat(stdoutChunks)));
    stream.on("error", reject);
  });

  const stderrPromise = new Promise<Buffer>((resolve, reject) => {
    const stream = child.stderr;
    if (!stream) {
      resolve(Buffer.alloc(0));
      return;
    }
    stream.on("data", (chunk: Buffer) => {
      stderrBytes += chunk.length;
      if (stderrBytes > limits.maxStderrBytes) {
        stderrOverflowed = true;
        killChild("SIGTERM");
        reject(
          new ShellguardLimitExceeded(
            "SHELLGUARD_STDERR_LIMIT",
            `stderr exceeded ${limits.maxStderrBytes} bytes`,
            { bytes: stderrBytes, limit: limits.maxStderrBytes },
          ),
        );
        return;
      }
      stderrChunks.push(chunk);
      opts.onStderrChunk?.(stderrBytes);
    });
    stream.on("end", () => resolve(Buffer.concat(stderrChunks)));
    stream.on("error", reject);
  });

  const exitPromise = new Promise<{
    exitCode: number;
    signal: NodeJS.Signals | null;
  }>((resolve, reject) => {
    child.on("exit", (code, signal) => {
      clearTimeout(timer);
      if (timedOut) {
        reject(
          new ShellguardTimeout(
            `process exceeded ${limits.timeoutMs} ms timeout`,
            { timeoutMs: limits.timeoutMs },
          ),
        );
        return;
      }
      if (stdoutOverflowed || stderrOverflowed) {
        // overflow path already rejected the stream promise; resolve
        // with sentinel so the awaiter can pick up the stream error
        resolve({ exitCode: code ?? -1, signal });
        return;
      }
      resolve({ exitCode: code ?? -1, signal });
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });

  return {
    stdoutPromise,
    stderrPromise,
    exitPromise,
    cleanup: () => {
      clearTimeout(timer);
    },
  };
}
