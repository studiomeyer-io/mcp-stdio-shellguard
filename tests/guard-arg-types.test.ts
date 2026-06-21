/**
 * Defense-in-depth: the guard wrappers must reject non-string args at the
 * JS boundary. The TS type is `string[]`, but the library is reachable
 * from untyped JS and JSON tool paths where an arg can arrive as a
 * number / object / null. Both the allowlist regex (`re.test`) and
 * `spawn` silently coerce such values, so a non-string arg could slip
 * past an argsPattern the operator believed constrained the input.
 *
 * Attack-blocked + benign-allowed for both guardExec and guardSpawn.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import { AllowlistRegistry } from "../src/guard/allowlist.js";
import { ReplayWindow } from "../src/guard/replay.js";
import { guardExec } from "../src/guard/exec.js";
import { guardSpawn } from "../src/guard/spawn.js";
import { ShellguardDenied } from "../src/guard/errors.js";

interface FakeChild extends EventEmitter {
  stdout: Readable;
  stderr: Readable;
  pid: number;
  kill: (signal?: string) => boolean;
}

function makeFakeChild(opts: { stdout?: string; exitCode?: number }): FakeChild {
  const child = new EventEmitter() as FakeChild;
  child.stdout = Readable.from(Buffer.from(opts.stdout ?? ""));
  child.stderr = Readable.from(Buffer.from(""));
  child.pid = 4242;
  child.kill = (): boolean => true;
  queueMicrotask(() => {
    child.emit("exit", opts.exitCode ?? 0, null);
    child.emit("close", opts.exitCode ?? 0, null);
  });
  return child;
}

const spawnImpl = (() => makeFakeChild({ stdout: "ok" })) as never;

describe("guardExec — arg type validation", () => {
  let registry: AllowlistRegistry;
  let replay: ReplayWindow;
  beforeEach(() => {
    registry = new AllowlistRegistry();
    replay = new ReplayWindow();
    // MEDIUM tier (empty argsPatterns) is the most exposed case: any
    // args allowed → coercion is the only thing standing between a
    // non-string arg and `spawn`.
    registry.register({
      toolName: "echo",
      executable: "/bin/echo",
      argsPatterns: [],
    });
  });

  it("ATTACK: a number arg is rejected (not coerced to a string)", async () => {
    await expect(
      guardExec(
        {
          toolName: "echo",
          command: "/bin/echo",
          args: [123 as unknown as string],
        },
        { registry, replay, spawnImpl },
      ),
    ).rejects.toThrow(/args\[0\] must be a string/);
  });

  it("ATTACK: an object arg is rejected", async () => {
    await expect(
      guardExec(
        {
          toolName: "echo",
          command: "/bin/echo",
          args: ["ok", {} as unknown as string],
        },
        { registry, replay, spawnImpl },
      ),
    ).rejects.toThrow(ShellguardDenied);
  });

  it("ATTACK: a null arg is rejected", async () => {
    await expect(
      guardExec(
        {
          toolName: "echo",
          command: "/bin/echo",
          args: [null as unknown as string],
        },
        { registry, replay, spawnImpl },
      ),
    ).rejects.toThrow(/must be a string/);
  });

  it("BENIGN: all-string args still run", async () => {
    const result = await guardExec(
      { toolName: "echo", command: "/bin/echo", args: ["hello", "world"] },
      { registry, replay, spawnImpl, now: () => 0 },
    );
    expect(result.stdout).toBe("ok");
    expect(result.exitCode).toBe(0);
  });

  it("BENIGN: empty args[] still run", async () => {
    const result = await guardExec(
      { toolName: "echo", command: "/bin/echo", args: [] },
      { registry, replay, spawnImpl, now: () => 0 },
    );
    expect(result.exitCode).toBe(0);
  });
});

describe("guardSpawn — arg type validation", () => {
  let registry: AllowlistRegistry;
  let replay: ReplayWindow;
  beforeEach(() => {
    registry = new AllowlistRegistry();
    replay = new ReplayWindow();
    registry.register({
      toolName: "echo",
      executable: "/bin/echo",
      argsPatterns: [],
    });
  });

  it("ATTACK: non-array args is rejected", async () => {
    await expect(
      guardSpawn(
        {
          toolName: "echo",
          file: "/bin/echo",
          args: "nope" as unknown as string[],
        },
        { registry, replay, spawnImpl },
      ),
    ).rejects.toThrow(/string\[\] vector/);
  });

  it("ATTACK: a number arg is rejected", async () => {
    await expect(
      guardSpawn(
        {
          toolName: "echo",
          file: "/bin/echo",
          args: [42 as unknown as string],
        },
        { registry, replay, spawnImpl },
      ),
    ).rejects.toThrow(/args\[0\] must be a string/);
  });

  it("BENIGN: all-string args still run", async () => {
    const result = await guardSpawn(
      { toolName: "echo", file: "/bin/echo", args: ["hello"] },
      { registry, replay, spawnImpl, now: () => 0 },
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdoutHash).toMatch(/^[0-9a-f]{64}$/);
  });
});
