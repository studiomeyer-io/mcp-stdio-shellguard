import { describe, it, expect } from "vitest";
import {
  canonicalize,
  canonicalHash,
  SEMANTIC_ENV_KEYS,
} from "../src/guard/canonical.js";

describe("canonical", () => {
  it("produces deterministic hash for identical inputs", () => {
    const a = canonicalHash({
      executable: "git",
      args: ["log", "--oneline"],
      cwd: "/tmp",
      env: { PATH: "/usr/bin", LANG: "C" },
    });
    const b = canonicalHash({
      executable: "git",
      args: ["log", "--oneline"],
      cwd: "/tmp",
      env: { PATH: "/usr/bin", LANG: "C" },
    });
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("differs when args differ", () => {
    const a = canonicalHash({ executable: "git", args: ["log"] });
    const b = canonicalHash({ executable: "git", args: ["status"] });
    expect(a).not.toBe(b);
  });

  it("ignores non-semantic env keys", () => {
    const a = canonicalHash({
      executable: "git",
      args: [],
      env: { PATH: "/u", PWD: "/a", TERM: "xterm" },
    });
    const b = canonicalHash({
      executable: "git",
      args: [],
      env: { PATH: "/u", PWD: "/different", TERM: "linux" },
    });
    expect(a).toBe(b);
  });

  it("changes when a semantic key changes", () => {
    const a = canonicalHash({ executable: "x", args: [], env: { PATH: "/a" } });
    const b = canonicalHash({ executable: "x", args: [], env: { PATH: "/b" } });
    expect(a).not.toBe(b);
  });

  it("env subset stays sorted (canonical form is order-independent)", () => {
    const a = canonicalize({
      executable: "x",
      args: [],
      env: { LANG: "C", PATH: "/u" },
    });
    const b = canonicalize({
      executable: "x",
      args: [],
      env: { PATH: "/u", LANG: "C" },
    });
    expect(a).toBe(b);
  });

  it("respects custom envKeys override", () => {
    const a = canonicalHash({
      executable: "x",
      args: [],
      env: { CUSTOM: "1" },
      envKeys: ["CUSTOM"],
    });
    const b = canonicalHash({
      executable: "x",
      args: [],
      env: { CUSTOM: "2" },
      envKeys: ["CUSTOM"],
    });
    expect(a).not.toBe(b);
  });

  it("SEMANTIC_ENV_KEYS contains PATH", () => {
    expect(SEMANTIC_ENV_KEYS).toContain("PATH");
    expect(SEMANTIC_ENV_KEYS).toContain("HOME");
  });
});
