/**
 * Round 2 Cold-Cross-Review Regression Tests (S991-Folge / S1011 Promotion).
 *
 * Three classes of bypass that two cold-cross reviewers (Critic +
 * Architect) flagged HIGH before v0.1.0 was promoted to GitHub +
 * npm. This file binds the fixes to executable behaviour so a
 * regression in v0.1.x cannot silently undo them.
 *
 * - HIGH-2.a: Allowlist-Regex bypass via Fullwidth + Zero-Width chars
 * - HIGH-2.b: Replay-Window bypass via Zero-Width chars
 * - HIGH-2.c: Unicode-whitespace smuggle past the exec/spawn `command`
 *             single-token check (originally `includes(" ")`)
 * - HIGH-3:   `shell_true_option` audit pattern only inspecting the
 *             last arg, missing `spawn(cmd, args, { shell: true }, cb)`
 */

import { describe, it, expect } from "vitest";
import { parse } from "@typescript-eslint/parser";
import type { TSESTree } from "@typescript-eslint/types";
import { AllowlistRegistry } from "../src/guard/allowlist.js";
import { canonicalHash } from "../src/guard/canonical.js";
import { ReplayWindow } from "../src/guard/replay.js";
import { guardExec } from "../src/guard/exec.js";
import { guardSpawn } from "../src/guard/spawn.js";
import { ShellguardDenied } from "../src/guard/errors.js";
import { evaluateCall } from "../src/audit/patterns.js";

function firstCall(src: string): TSESTree.CallExpression {
  const ast = parse(src, {
    loc: true,
    range: true,
    ecmaVersion: "latest",
    sourceType: "module",
  });
  let found: TSESTree.CallExpression | null = null;
  function walk(node: TSESTree.Node | null | undefined): void {
    if (!node || found) return;
    if (node.type === "CallExpression") {
      found = node;
      return;
    }
    for (const key of Object.keys(node) as Array<keyof typeof node>) {
      const child = node[key] as unknown;
      if (Array.isArray(child)) {
        for (const c of child) {
          if (c && typeof c === "object" && "type" in c) {
            walk(c as TSESTree.Node);
            if (found) return;
          }
        }
      } else if (child && typeof child === "object" && "type" in child) {
        walk(child as TSESTree.Node);
        if (found) return;
      }
    }
  }
  walk(ast as TSESTree.Node);
  if (!found) throw new Error("no call expression found in: " + src);
  return found;
}

describe("HIGH-2.a — Allowlist-Regex Unicode-Bypass-Defense", () => {
  it("rejects fullwidth-letter substitution past argsPattern (Cold-Cross Critic, S991-Folge)", () => {
    // Pre-fix: regex `^log$` ran against raw arg, fullwidth chars
    // bypassed the literal-match. Post-fix: NFKC collapses to ASCII
    // so the regex catches `ｌｏｇ` as "log" — but the
    // fact-of-the-bypass-attempt is preserved. The decision must
    // reflect the canonical form, not the wire form.
    const r = new AllowlistRegistry();
    r.register({
      toolName: "git-log",
      executable: "/usr/bin/git",
      argsPatterns: ["^log$", "^--oneline$"],
    });
    const m = r.match({
      toolName: "git-log",
      executable: "/usr/bin/git",
      args: ["ｌｏｇ", "--oneline"],
    });
    expect(m.allowed).toBe(true);
  });

  it("zero-width chars do not let an attacker register-then-bypass a stricter pattern", () => {
    // An attacker who knows the registered pattern is `^log$` would
    // submit `log​` hoping the regex misses it (raw `log​`
    // does not match `^log$`). After normalisation, the raw arg is
    // collapsed to "log", which DOES match. Result: allowed (the
    // sandbox + replay layers are the next gate). The point of this
    // test is that we do not accidentally GRANT a path that should
    // have been denied because the registered pattern was
    // `^log[a-z]+$`.
    const r = new AllowlistRegistry();
    r.register({
      toolName: "t",
      executable: "/usr/bin/git",
      argsPatterns: ["^log[a-z]+$"], // requires extra letters after "log"
    });
    // raw "log" — should be denied because the registered pattern
    // requires letters after "log".
    const denied = r.match({
      toolName: "t",
      executable: "/usr/bin/git",
      args: ["log"],
    });
    expect(denied.allowed).toBe(false);
    // raw "log​" — even with normalisation, the normalised form
    // is just "log", which still does NOT match `^log[a-z]+$`.
    // The defense must NOT silently grant.
    const stillDenied = r.match({
      toolName: "t",
      executable: "/usr/bin/git",
      args: ["log​"],
    });
    expect(stillDenied.allowed).toBe(false);
  });

  it("strips bidi-override + ZWJ before regex match (anti-smuggle)", () => {
    const r = new AllowlistRegistry();
    r.register({
      toolName: "t",
      executable: "/usr/bin/git",
      argsPatterns: ["^log$"],
    });
    const m = r.match({
      toolName: "t",
      executable: "/usr/bin/git",
      args: ["lo‍‮g"],
    });
    expect(m.allowed).toBe(true); // normalised to "log"
  });

  it("preserves the wire-form arg in the failure reason (audit trail)", () => {
    const r = new AllowlistRegistry();
    r.register({
      toolName: "t",
      executable: "/usr/bin/git",
      argsPatterns: ["^log$"],
    });
    const m = r.match({
      toolName: "t",
      executable: "/usr/bin/git",
      args: ["evil​"],
    });
    expect(m.allowed).toBe(false);
    // the error message contains the wire-form (with ZWC), not the
    // normalised form, so an auditor can see what was sent.
    expect(m.reason).toContain("evil​");
  });
});

describe("HIGH-2.b — Replay-Window Unicode-Bypass-Defense", () => {
  it("zero-width-suffixed args produce the same canonical hash (Cold-Cross Critic, replay TTL bypass closed)", () => {
    const a = canonicalHash({
      executable: "/usr/bin/git",
      args: ["log", "--oneline"],
    });
    const b = canonicalHash({
      executable: "/usr/bin/git",
      args: ["log​", "--oneline"],
    });
    const c = canonicalHash({
      executable: "/usr/bin/git",
      args: ["log‍﻿", "--oneline"],
    });
    expect(a).toBe(b);
    expect(b).toBe(c);
  });

  it("fullwidth-letter args collapse to the ASCII canonical hash", () => {
    const ascii = canonicalHash({
      executable: "/usr/bin/git",
      args: ["log"],
    });
    const fullwidth = canonicalHash({
      executable: "/usr/bin/git",
      args: ["ｌｏｇ"],
    });
    expect(fullwidth).toBe(ascii);
  });

  it("replay window hits the second call even when the attacker varies ZWC", () => {
    const w = new ReplayWindow({ ttlMs: 60_000, maxEntries: 1024 });
    const h1 = canonicalHash({
      executable: "/usr/bin/git",
      args: ["log"],
    });
    const r1 = w.record(h1);
    expect(r1.isReplay).toBe(false);

    const h2 = canonicalHash({
      executable: "/usr/bin/git",
      args: ["log‍"],
    });
    expect(h2).toBe(h1);
    const r2 = w.record(h2);
    expect(r2.isReplay).toBe(true);
  });

  it("env values are also normalised before hashing", () => {
    const a = canonicalHash({
      executable: "/usr/bin/git",
      args: ["log"],
      env: { LANG: "en_US.UTF-8" },
    });
    const b = canonicalHash({
      executable: "/usr/bin/git",
      args: ["log"],
      env: { LANG: "en_US.UTF-8​" },
    });
    expect(a).toBe(b);
  });
});

describe("HIGH-2.c — exec/spawn Unicode-whitespace single-token check", () => {
  it("guardExec rejects U+3000 ideographic-space-smuggled command", async () => {
    const r = new AllowlistRegistry();
    const replay = new ReplayWindow();
    r.register({
      toolName: "t",
      executable: "/usr/bin/sh",
      argsPatterns: [],
    });
    await expect(
      guardExec(
        {
          toolName: "t",
          command: "/usr/bin/sh　-c", // CJK fullwidth space
          args: [],
        },
        { registry: r, replay },
      ),
    ).rejects.toThrow(ShellguardDenied);
  });

  it("guardExec rejects U+00A0 no-break-space-smuggled command", async () => {
    const r = new AllowlistRegistry();
    const replay = new ReplayWindow();
    await expect(
      guardExec(
        {
          toolName: "t",
          command: "/usr/bin/sh -c",
          args: [],
        },
        { registry: r, replay },
      ),
    ).rejects.toThrow(ShellguardDenied);
  });

  it("guardSpawn rejects U+200B-suffixed file path", async () => {
    const r = new AllowlistRegistry();
    const replay = new ReplayWindow();
    // FEFF (BOM) sits in our whitespace set.
    await expect(
      guardSpawn(
        {
          toolName: "t",
          file: "/usr/bin/git﻿",
          args: [],
        },
        { registry: r, replay },
      ),
    ).rejects.toThrow(ShellguardDenied);
  });

  it("guardSpawn rejects EN-SPACE-smuggled file path", async () => {
    const r = new AllowlistRegistry();
    const replay = new ReplayWindow();
    await expect(
      guardSpawn(
        {
          toolName: "t",
          file: "/usr/bin/git --exec",
          args: [],
        },
        { registry: r, replay },
      ),
    ).rejects.toThrow(ShellguardDenied);
  });

  it("regression: classic ASCII-space command is still rejected", async () => {
    const r = new AllowlistRegistry();
    const replay = new ReplayWindow();
    await expect(
      guardExec(
        {
          toolName: "t",
          command: "/usr/bin/sh -c",
          args: [],
        },
        { registry: r, replay },
      ),
    ).rejects.toThrow(ShellguardDenied);
  });
});

describe("HIGH-3 — shell_true_option audit pattern is position-agnostic", () => {
  it("catches { shell: true } when it is the LAST arg (regression)", () => {
    const c = firstCall(`spawn('git', ['log'], { shell: true })`);
    const matches = evaluateCall(c);
    expect(matches.some((m) => m.id === "shell_true_option")).toBe(true);
  });

  it("catches { shell: true } when followed by a callback (S991-Folge fix)", () => {
    const c = firstCall(
      `child_process.spawn('git', ['log'], { shell: true }, cb)`,
    );
    const matches = evaluateCall(c);
    expect(matches.some((m) => m.id === "shell_true_option")).toBe(true);
  });

  it("catches { shell: true } in exec(cmd, opts, cb) form", () => {
    const c = firstCall(
      `child_process.exec('ls', { shell: true }, function (err, out) {})`,
    );
    const matches = evaluateCall(c);
    expect(matches.some((m) => m.id === "shell_true_option")).toBe(true);
  });

  it("catches { shell: true } in execFile(file, args, opts, cb)", () => {
    const c = firstCall(
      `cp.execFile('git', ['log'], { shell: true }, function () {})`,
    );
    const matches = evaluateCall(c);
    expect(matches.some((m) => m.id === "shell_true_option")).toBe(true);
  });

  it("does NOT fire when shell is literal-false (no false positive)", () => {
    const c = firstCall(
      `child_process.spawn('git', ['log'], { shell: false }, cb)`,
    );
    const matches = evaluateCall(c);
    expect(matches.some((m) => m.id === "shell_true_option")).toBe(false);
  });
});
