import { describe, it, expect, beforeEach } from "vitest";
import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import { AllowlistRegistry } from "../src/guard/allowlist.js";
import { ReplayWindow } from "../src/guard/replay.js";
import { guardSpawn } from "../src/guard/spawn.js";
import { ShellguardDenied } from "../src/guard/errors.js";

interface FakeChild extends EventEmitter {
  stdout: Readable;
  stderr: Readable;
  pid: number;
  kill: (signal?: string) => boolean;
}

function makeFakeChild(opts: {
  stdout?: string;
  stderr?: string;
  exitCode?: number;
}): FakeChild {
  const child = new EventEmitter() as FakeChild;
  child.stdout = Readable.from(Buffer.from(opts.stdout ?? ""));
  child.stderr = Readable.from(Buffer.from(opts.stderr ?? ""));
  child.pid = 4242;
  child.kill = (): boolean => true;
  queueMicrotask(() => {
    child.emit("exit", opts.exitCode ?? 0, null);
    child.emit("close", opts.exitCode ?? 0, null);
  });
  return child;
}

describe("guardSpawn — hard denials", () => {
  let registry: AllowlistRegistry;
  let replay: ReplayWindow;
  beforeEach(() => {
    registry = new AllowlistRegistry();
    replay = new ReplayWindow();
  });

  it("rejects shell:true unconditionally", async () => {
    registry.register({
      toolName: "t",
      executable: "/usr/bin/git",
      argsPatterns: [],
    });
    await expect(
      guardSpawn(
        {
          toolName: "t",
          file: "/usr/bin/git",
          args: ["log"],
          shell: true,
        },
        {
          registry,
          replay,
          spawnImpl: (() => makeFakeChild({})) as never,
        },
      ),
    ).rejects.toThrow(/shell:true is forbidden/);
  });

  it("rejects shell-string file (contains space)", async () => {
    await expect(
      guardSpawn(
        { toolName: "t", file: "ls -la", args: [] },
        {
          registry,
          replay,
          spawnImpl: (() => makeFakeChild({})) as never,
        },
      ),
    ).rejects.toThrow(/shell string/);
  });

  it("rejects unregistered tool", async () => {
    await expect(
      guardSpawn(
        { toolName: "unknown", file: "/bin/ls", args: [] },
        {
          registry,
          replay,
          spawnImpl: (() => makeFakeChild({})) as never,
        },
      ),
    ).rejects.toThrow(ShellguardDenied);
  });
});

describe("guardSpawn — happy path", () => {
  let registry: AllowlistRegistry;
  let replay: ReplayWindow;
  beforeEach(() => {
    registry = new AllowlistRegistry();
    replay = new ReplayWindow();
    registry.register({
      toolName: "git-log",
      executable: "/usr/bin/git",
      argsPatterns: ["^log$"],
    });
  });

  it("returns stdoutHash/stderrHash + tier + canonical hash", async () => {
    const result = await guardSpawn(
      {
        toolName: "git-log",
        file: "/usr/bin/git",
        args: ["log"],
      },
      {
        registry,
        replay,
        spawnImpl: (() =>
          makeFakeChild({
            stdout: "deadbeef commit",
            stderr: "",
          })) as never,
      },
    );
    expect(result.stdoutHash).toMatch(/^[0-9a-f]{64}$/);
    expect(result.stderrHash).toMatch(/^[0-9a-f]{64}$/);
    expect(result.canonicalHash).toMatch(/^[0-9a-f]{64}$/);
    expect(result.trustTier).toBe("CRITICAL");
    expect(result.pid).toBe(4242);
  });

  it("fdBudget can be tightened by caller, never widened", async () => {
    const result = await guardSpawn(
      {
        toolName: "git-log",
        file: "/usr/bin/git",
        args: ["log"],
        fdBudget: 4, // tighter than standard profile
      },
      {
        registry,
        replay,
        spawnImpl: (() => makeFakeChild({})) as never,
      },
    );
    expect(result.fdBudget).toBe(4);
  });

  it("isReplay=true on the second invocation with same canonical hash", async () => {
    const spawnImpl = (() => makeFakeChild({})) as never;
    const a = await guardSpawn(
      { toolName: "git-log", file: "/usr/bin/git", args: ["log"] },
      { registry, replay, spawnImpl },
    );
    const b = await guardSpawn(
      { toolName: "git-log", file: "/usr/bin/git", args: ["log"] },
      { registry, replay, spawnImpl },
    );
    expect(a.isReplay).toBe(false);
    expect(b.isReplay).toBe(true);
    expect(a.canonicalHash).toBe(b.canonicalHash);
  });
});
