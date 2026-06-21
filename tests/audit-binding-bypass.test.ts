/**
 * Regression tests for the alias / shell-string bypass class found in
 * the cold-cross review of v0.1.1.
 *
 * Each block ships BOTH an attack-blocked case (the audit must flag the
 * dangerous shape) AND a benign-allowed case (the audit must stay silent
 * so the layer cannot regress into false positives). A security scanner
 * that screams at safe code gets disabled, which is itself a vuln.
 */

import { describe, it, expect } from "vitest";
import path from "node:path";
import { promises as fs } from "node:fs";
import os from "node:os";
import { scanPath } from "../src/audit/scanner.js";
import { parse } from "@typescript-eslint/parser";
import type { TSESTree } from "@typescript-eslint/types";
import { resolveBindings, resolveCallMethod } from "../src/audit/bindings.js";

/** Write `code` to a temp .ts file and scan it at the given floor. */
async function scanCode(
  code: string,
  floor: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" = "LOW",
): Promise<string[]> {
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "sg-bind-"));
  const file = path.join(tmp, "probe.ts");
  await fs.writeFile(file, code, "utf8");
  const result = await scanPath(file, { severityFloor: floor });
  expect(result.errors).toEqual([]);
  return result.findings.map((f) => f.id);
}

function firstCallNamed(src: string, name: string): TSESTree.CallExpression {
  const ast = parse(src, {
    loc: true,
    range: true,
    ecmaVersion: "latest",
    sourceType: "module",
  });
  let found: TSESTree.CallExpression | null = null;
  function walk(node: TSESTree.Node | null | undefined): void {
    if (!node || found) return;
    if (
      node.type === "CallExpression" &&
      ((node.callee.type === "Identifier" && node.callee.name === name) ||
        (node.callee.type === "MemberExpression" &&
          node.callee.property.type === "Identifier" &&
          node.callee.property.name === name))
    ) {
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
  if (!found) throw new Error(`no call to '${name}' found`);
  return found;
}

describe("alias bypass — promisify(exec)", () => {
  it("ATTACK: const execAsync = promisify(exec) is flagged CRITICAL", async () => {
    const ids = await scanCode(
      [
        `import { exec } from "node:child_process";`,
        `import { promisify } from "node:util";`,
        `const execAsync = promisify(exec);`,
        `export async function run(userInput: string) {`,
        `  return execAsync(\`ls \${userInput}\`);`,
        `}`,
        ``,
      ].join("\n"),
    );
    expect(ids).toContain("exec_template_literal_with_input");
  });

  it("ATTACK: util.promisify(cp.exec) member form is flagged CRITICAL", async () => {
    const ids = await scanCode(
      [
        `import * as cp from "node:child_process";`,
        `import * as util from "node:util";`,
        `const ea = util.promisify(cp.exec);`,
        `export function run(x: string) { return ea(\`ls \${x}\`); }`,
        ``,
      ].join("\n"),
    );
    expect(ids).toContain("exec_template_literal_with_input");
  });

  it("BENIGN: promisify of a non-child_process fn (readFile) stays clean", async () => {
    const ids = await scanCode(
      [
        `import { promisify } from "node:util";`,
        `import { readFile } from "node:fs";`,
        `const rf = promisify(readFile);`,
        `export function run(x: string) { return rf(\`/tmp/\${x}\`); }`,
        ``,
      ].join("\n"),
    );
    expect(ids).toEqual([]);
  });
});

describe("alias bypass — renamed imports / require", () => {
  it("ATTACK: import { exec as run } alias is flagged", async () => {
    const ids = await scanCode(
      [
        `import { exec as run } from "node:child_process";`,
        `export function go(x: string) { return run(\`ls \${x}\`); }`,
        ``,
      ].join("\n"),
    );
    expect(ids).toContain("exec_template_literal_with_input");
  });

  it("ATTACK: default import bound to arbitrary name (cpmod.exec) is flagged", async () => {
    const ids = await scanCode(
      [
        `import cpmod from "node:child_process";`,
        `export function go(x: string) { return cpmod.exec(\`ls \${x}\`); }`,
        ``,
      ].join("\n"),
    );
    expect(ids).toContain("exec_template_literal_with_input");
  });

  it("ATTACK: require destructure-rename (const { exec: sh }) is flagged", async () => {
    const ids = await scanCode(
      [
        `const { exec: sh } = require("child_process");`,
        `export function go(x: string) { return sh(\`ls \${x}\`); }`,
        ``,
      ].join("\n"),
    );
    expect(ids).toContain("exec_template_literal_with_input");
  });

  it("BENIGN: destructure exec from a non-child_process module stays clean", async () => {
    // The binding resolver must NOT attribute this to child_process.
    const bindings = resolveBindings(
      parse(`const { exec } = require("./my-shell-lib");`, {
        loc: true,
        range: true,
        ecmaVersion: "latest",
        sourceType: "module",
      }) as unknown as TSESTree.Node,
    );
    expect(bindings.identifierToMethod.has("exec")).toBe(false);
  });
});

describe("sync variants — spawnSync / execFileSync", () => {
  it("ATTACK: spawnSync('sh', ['-c', x], { shell: true }) is flagged HIGH", async () => {
    const ids = await scanCode(
      [
        `import { spawnSync } from "node:child_process";`,
        `export function run(x: string) {`,
        `  return spawnSync("sh", ["-c", x], { shell: true });`,
        `}`,
        ``,
      ].join("\n"),
      "HIGH",
    );
    expect(ids).toContain("shell_true_option");
  });

  it("ATTACK: execFileSync(<dynamic>) is flagged HIGH", async () => {
    const ids = await scanCode(
      [
        `import { execFileSync } from "node:child_process";`,
        `export function run(bin: string) { return execFileSync(bin); }`,
        ``,
      ].join("\n"),
      "HIGH",
    );
    expect(ids).toContain("exec_file_dynamic");
  });

  it("BENIGN: spawnSync(literal, literal-array, timeout) stays HIGH-clean", async () => {
    const ids = await scanCode(
      [
        `import { spawnSync } from "node:child_process";`,
        `export function run() {`,
        `  return spawnSync("/usr/bin/git", ["log"], { timeout: 5000 });`,
        `}`,
        ``,
      ].join("\n"),
      "HIGH",
    );
    expect(ids).toEqual([]);
  });
});

describe("shell-string bypass — { shell: '/bin/sh' }", () => {
  it("ATTACK: { shell: '/bin/bash' } string shell is flagged HIGH", async () => {
    const ids = await scanCode(
      [
        `import { spawn } from "node:child_process";`,
        `export function run(x: string) {`,
        `  return spawn("git", [x], { shell: "/bin/bash" });`,
        `}`,
        ``,
      ].join("\n"),
      "HIGH",
    );
    expect(ids).toContain("shell_true_option");
  });

  it("ATTACK: dynamic shell value (variable) is flagged HIGH", async () => {
    const ids = await scanCode(
      [
        `import { spawn } from "node:child_process";`,
        `export function run(sh: string) {`,
        `  return spawn("git", ["log"], { shell: sh });`,
        `}`,
        ``,
      ].join("\n"),
      "HIGH",
    );
    expect(ids).toContain("shell_true_option");
  });

  it("BENIGN: { shell: false } is NOT flagged", async () => {
    const ids = await scanCode(
      [
        `import { spawn } from "node:child_process";`,
        `export function run() {`,
        `  return spawn("git", ["log"], { shell: false, timeout: 5000 });`,
        `}`,
        ``,
      ].join("\n"),
      "HIGH",
    );
    expect(ids).toEqual([]);
  });

  it("BENIGN: empty string shell ({ shell: '' }) is NOT flagged", async () => {
    const ids = await scanCode(
      [
        `import { spawn } from "node:child_process";`,
        `export function run() {`,
        `  return spawn("git", ["log"], { shell: "", timeout: 5000 });`,
        `}`,
        ``,
      ].join("\n"),
      "HIGH",
    );
    expect(ids).toEqual([]);
  });
});

describe("binding resolver unit — resolveCallMethod", () => {
  it("resolves a promisified alias to its method", () => {
    const src = [
      `import { exec } from "node:child_process";`,
      `import { promisify } from "node:util";`,
      `const ea = promisify(exec);`,
      `ea("x");`,
    ].join("\n");
    const ast = parse(src, {
      loc: true,
      range: true,
      ecmaVersion: "latest",
      sourceType: "module",
    }) as unknown as TSESTree.Node;
    const bindings = resolveBindings(ast);
    const call = firstCallNamed(src, "ea");
    expect(resolveCallMethod(call, bindings)).toBe("exec");
  });

  it("returns null for an unrelated identifier", () => {
    const src = `helper("x");`;
    const ast = parse(src, {
      loc: true,
      range: true,
      ecmaVersion: "latest",
      sourceType: "module",
    }) as unknown as TSESTree.Node;
    const bindings = resolveBindings(ast);
    const call = firstCallNamed(src, "helper");
    expect(resolveCallMethod(call, bindings)).toBeNull();
  });
});
