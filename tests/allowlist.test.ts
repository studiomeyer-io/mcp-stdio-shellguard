import { describe, it, expect } from "vitest";
import { AllowlistRegistry } from "../src/guard/allowlist.js";
import { ShellguardError } from "../src/guard/errors.js";

describe("AllowlistRegistry", () => {
  it("default-deny when tool not registered", () => {
    const r = new AllowlistRegistry();
    const m = r.match({ toolName: "x", executable: "/bin/ls", args: [] });
    expect(m.allowed).toBe(false);
    expect(m.reason).toMatch(/not registered/);
  });

  it("registers and matches a simple entry", () => {
    const r = new AllowlistRegistry();
    r.register({
      toolName: "git-log",
      executable: "/usr/bin/git",
      argsPatterns: ["^log$", "^--oneline$"],
    });
    const m = r.match({
      toolName: "git-log",
      executable: "/usr/bin/git",
      args: ["log", "--oneline"],
    });
    expect(m.allowed).toBe(true);
    expect(m.entry?.argsRegex.length).toBe(2);
  });

  it("denies when executable mismatch", () => {
    const r = new AllowlistRegistry();
    r.register({
      toolName: "t",
      executable: "/usr/bin/git",
      argsPatterns: [],
    });
    const m = r.match({ toolName: "t", executable: "/usr/bin/sh", args: [] });
    expect(m.allowed).toBe(false);
    expect(m.reason).toMatch(/executable mismatch/);
  });

  it("denies when arg does not match any regex", () => {
    const r = new AllowlistRegistry();
    r.register({
      toolName: "t",
      executable: "/usr/bin/git",
      argsPatterns: ["^status$"],
    });
    const m = r.match({
      toolName: "t",
      executable: "/usr/bin/git",
      args: ["push"],
    });
    expect(m.allowed).toBe(false);
    expect(m.reason).toMatch(/does not match/);
  });

  it("allows any args when argsPatterns is empty", () => {
    const r = new AllowlistRegistry();
    r.register({
      toolName: "t",
      executable: "/usr/bin/git",
      argsPatterns: [],
    });
    const m = r.match({
      toolName: "t",
      executable: "/usr/bin/git",
      args: ["anything", "goes"],
    });
    expect(m.allowed).toBe(true);
  });

  it("cwdPattern is enforced when set", () => {
    const r = new AllowlistRegistry();
    r.register({
      toolName: "t",
      executable: "/usr/bin/git",
      argsPatterns: [],
      cwdPattern: "/tmp/**",
    });
    expect(
      r.match({
        toolName: "t",
        executable: "/usr/bin/git",
        args: [],
        cwd: "/tmp/foo/bar",
      }).allowed,
    ).toBe(true);
    expect(
      r.match({
        toolName: "t",
        executable: "/usr/bin/git",
        args: [],
        cwd: "/etc",
      }).allowed,
    ).toBe(false);
  });

  it("rejects invalid regex on register", () => {
    const r = new AllowlistRegistry();
    expect(() =>
      r.register({
        toolName: "t",
        executable: "/x",
        argsPatterns: ["[unterminated"],
      }),
    ).toThrow(ShellguardError);
  });

  it("requires toolName + executable on register", () => {
    const r = new AllowlistRegistry();
    expect(() =>
      r.register({
        toolName: "",
        executable: "/x",
        argsPatterns: [],
      }),
    ).toThrow(ShellguardError);
  });

  it("unregister removes an entry", () => {
    const r = new AllowlistRegistry();
    r.register({
      toolName: "t",
      executable: "/x",
      argsPatterns: [],
    });
    expect(r.has("t")).toBe(true);
    expect(r.unregister("t")).toBe(true);
    expect(r.has("t")).toBe(false);
    expect(r.unregister("t")).toBe(false);
  });

  it("list and clear work", () => {
    const r = new AllowlistRegistry();
    r.register({ toolName: "a", executable: "/a", argsPatterns: [] });
    r.register({ toolName: "b", executable: "/b", argsPatterns: [] });
    expect(r.list().length).toBe(2);
    r.clear();
    expect(r.list().length).toBe(0);
  });

  it("default sandboxProfile is standard", () => {
    const r = new AllowlistRegistry();
    const e = r.register({ toolName: "t", executable: "/x", argsPatterns: [] });
    expect(e.sandboxProfile).toBe("standard");
  });
});
