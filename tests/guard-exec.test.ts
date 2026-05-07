import { describe, it, expect, beforeEach } from "vitest";
import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import { AllowlistRegistry } from "../src/guard/allowlist.js";
import { ReplayWindow } from "../src/guard/replay.js";
import { guardExec } from "../src/guard/exec.js";
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
  // simulate close after streams drain
  queueMicrotask(() => {
    child.emit("exit", opts.exitCode ?? 0, null);
    child.emit("close", opts.exitCode ?? 0, null);
  });
  return child;
}

describe("guardExec — denial paths", () => {
  let registry: AllowlistRegistry;
  let replay: ReplayWindow;
  beforeEach(() => {
    registry = new AllowlistRegistry();
    replay = new ReplayWindow();
  });

  it("rejects empty command", async () => {
    await expect(
      guardExec(
        { toolName: "t", command: "", args: [] },
        {
          registry,
          replay,
          spawnImpl: (() => makeFakeChild({})) as never,
        },
      ),
    ).rejects.toThrow(ShellguardDenied);
  });

  it("rejects shell-string command (contains space)", async () => {
    await expect(
      guardExec(
        { toolName: "t", command: "ls -la", args: [] },
        {
          registry,
          replay,
          spawnImpl: (() => makeFakeChild({})) as never,
        },
      ),
    ).rejects.toThrow(/shell string/);
  });

  it("rejects non-array args", async () => {
    await expect(
      guardExec(
        {
          toolName: "t",
          command: "/bin/ls",
          args: "not-an-array" as unknown as string[],
        },
        {
          registry,
          replay,
          spawnImpl: (() => makeFakeChild({})) as never,
        },
      ),
    ).rejects.toThrow(/string\[\] vector/);
  });

  it("rejects unregistered tool (default-deny)", async () => {
    await expect(
      guardExec(
        { toolName: "unregistered", command: "/bin/ls", args: [] },
        {
          registry,
          replay,
          spawnImpl: (() => makeFakeChild({})) as never,
        },
      ),
    ).rejects.toThrow(ShellguardDenied);
  });

  it("rejects executable mismatch", async () => {
    registry.register({
      toolName: "t",
      executable: "/usr/bin/git",
      argsPatterns: [],
    });
    await expect(
      guardExec(
        { toolName: "t", command: "/usr/bin/sh", args: [] },
        {
          registry,
          replay,
          spawnImpl: (() => makeFakeChild({})) as never,
        },
      ),
    ).rejects.toThrow(/executable mismatch/);
  });

  it("blockOnReplay throws on second call with same canonical hash", async () => {
    registry.register({
      toolName: "t",
      executable: "/usr/bin/git",
      argsPatterns: [],
    });
    const spawnImpl = (() => makeFakeChild({ stdout: "ok" })) as never;
    await guardExec(
      { toolName: "t", command: "/usr/bin/git", args: ["log"] },
      { registry, replay, spawnImpl },
    );
    await expect(
      guardExec(
        {
          toolName: "t",
          command: "/usr/bin/git",
          args: ["log"],
          blockOnReplay: true,
        },
        { registry, replay, spawnImpl },
      ),
    ).rejects.toThrow(/replay/);
  });
});

describe("guardExec — happy path", () => {
  let registry: AllowlistRegistry;
  let replay: ReplayWindow;
  beforeEach(() => {
    registry = new AllowlistRegistry();
    replay = new ReplayWindow();
    registry.register({
      toolName: "git-log",
      executable: "/usr/bin/git",
      argsPatterns: ["^log$", "^--oneline$"],
    });
  });

  it("returns stdout/stderr/exitCode + canonical hash + tier", async () => {
    const result = await guardExec(
      {
        toolName: "git-log",
        command: "/usr/bin/git",
        args: ["log", "--oneline"],
      },
      {
        registry,
        replay,
        spawnImpl: (() =>
          makeFakeChild({
            stdout: "abc123 commit message",
            stderr: "",
            exitCode: 0,
          })) as never,
        now: () => 0,
      },
    );
    expect(result.stdout).toBe("abc123 commit message");
    expect(result.stderr).toBe("");
    expect(result.exitCode).toBe(0);
    expect(result.canonicalHash).toMatch(/^[0-9a-f]{64}$/);
    expect(result.trustTier).toBe("CRITICAL");
    expect(result.isReplay).toBe(false);
  });

  it("second call with same args reports isReplay=true", async () => {
    const spawnImpl = (() => makeFakeChild({ stdout: "" })) as never;
    const a = await guardExec(
      {
        toolName: "git-log",
        command: "/usr/bin/git",
        args: ["log", "--oneline"],
      },
      { registry, replay, spawnImpl },
    );
    const b = await guardExec(
      {
        toolName: "git-log",
        command: "/usr/bin/git",
        args: ["log", "--oneline"],
      },
      { registry, replay, spawnImpl },
    );
    expect(a.isReplay).toBe(false);
    expect(b.isReplay).toBe(true);
    expect(a.canonicalHash).toBe(b.canonicalHash);
  });

  it("denies args that don't match argsPatterns", async () => {
    await expect(
      guardExec(
        {
          toolName: "git-log",
          command: "/usr/bin/git",
          args: ["push", "origin"],
        },
        {
          registry,
          replay,
          spawnImpl: (() => makeFakeChild({})) as never,
        },
      ),
    ).rejects.toThrow(ShellguardDenied);
  });
});
