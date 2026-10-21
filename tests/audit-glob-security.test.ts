import { afterEach, describe, expect, it } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanPath } from "../src/audit/scanner.js";

let temporary: string | undefined;
afterEach(async () => { if (temporary) await fs.rm(temporary, { recursive: true, force: true }); temporary = undefined; });

async function fixture(): Promise<string> {
  temporary = await fs.mkdtemp(path.join(os.tmpdir(), "sg-glob-security-"));
  await fs.writeFile(path.join(temporary, "safe.ts"), "export const safe = true;");
  return temporary;
}

describe("audit glob safety", () => {
  it("rejects a deeply nested ignore pattern", async () => {
    const root = await fixture();
    const hostile = "{".repeat(4500) + "a" + "}".repeat(4500);
    await expect(scanPath(root, { ignoreGlobs: [hostile] })).rejects.toThrow(/1024 characters/);
  });

  it.each(["**/*.{js,tsx}", "**/*.+(js|tsx)"])("preserves the ignore pattern %s", async (pattern) => {
    const root = await fixture();
    await fs.writeFile(path.join(root, "ignored.js"), "export const ignored = true;");
    await fs.writeFile(path.join(root, "ignored.tsx"), "export const ignored = true;");
    await fs.writeFile(path.join(root, ".hidden.ts"), "export const hidden = true;");
    await fs.mkdir(path.join(root, "node_modules"));
    await fs.writeFile(path.join(root, "node_modules", "ignored.ts"), "export const ignored = true;");
    const result = await scanPath(root, { ignoreGlobs: [pattern] });
    expect(result.errors).toEqual([]);
    expect(result.summary.filesScanned).toBe(1);
  });
});


describe("external glob complexity budget", () => {
  it("rejects 129 patterns", async () => {
    const root = await fixture();
    await expect(scanPath(root, { ignoreGlobs: Array.from({ length: 129 }, () => "**/*.ts") })).rejects.toThrow(/128 glob patterns/);
  });
  it("rejects a 1025 character pattern", async () => {
    const root = await fixture();
    await expect(scanPath(root, { ignoreGlobs: ["a".repeat(1025)] })).rejects.toThrow(/1024 characters/);
  });
  it("rejects the nested extglob attack", async () => {
    const root = await fixture();
    await expect(scanPath(root, { ignoreGlobs: ["+(".repeat(4500) + "x" + ")".repeat(4500)] })).rejects.toThrow(/1024 characters/);
  });
  it("rejects 17 unescaped opening groups", async () => {
    const root = await fixture();
    await expect(scanPath(root, { ignoreGlobs: ["[ab]".repeat(17)] })).rejects.toThrow(/16 unescaped/);
  });
  it("rejects unmatched opening groups", async () => {
    const root = await fixture();
    await expect(scanPath(root, { ignoreGlobs: ["(".repeat(17) + "a"] })).rejects.toThrow(/16 unescaped/);
  });
  it("counts groups after an escaped backslash", async () => {
    const root = await fixture();
    await expect(scanPath(root, { ignoreGlobs: ["\\\\(".repeat(17)] })).rejects.toThrow(/16 unescaped/);
  });
  it("accepts 128 patterns", async () => {
    const root = await fixture();
    const result = await scanPath(root, { ignoreGlobs: Array.from({ length: 128 }, (_, index) => `unmatched-${index}`) });
    expect(result.summary.filesScanned).toBe(1);
  });
  it("accepts exactly 1024 characters and 16 groups", async () => {
    const root = await fixture();
    const boundary = "**/" + "a/".repeat(508) + "a*.ts";
    expect(boundary).toHaveLength(1024);
    await expect(scanPath(root, { ignoreGlobs: [boundary, "[ab]".repeat(16)] })).resolves.toBeDefined();
  });
  it("does not count escaped opening groups", async () => {
    const root = await fixture();
    await expect(scanPath(root, { ignoreGlobs: ["\\(".repeat(17)] })).resolves.toBeDefined();
  });
});
