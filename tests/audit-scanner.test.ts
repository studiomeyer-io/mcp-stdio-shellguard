import { describe, it, expect } from "vitest";
import path from "node:path";
import { promises as fs } from "node:fs";
import os from "node:os";
import { scanPath, relativiseFindings } from "../src/audit/scanner.js";

const FIXTURES = path.resolve(__dirname, "..", "fixtures");

describe("scanPath — fixtures", () => {
  it("vulnerable-server-A produces >=3 CRITICAL + >=2 HIGH (success criterion)", async () => {
    const result = await scanPath(path.join(FIXTURES, "vulnerable-server-A"));
    expect(result.errors).toEqual([]);
    expect(result.summary.bySeverity.CRITICAL).toBeGreaterThanOrEqual(3);
    expect(result.summary.bySeverity.HIGH).toBeGreaterThanOrEqual(2);
  });

  it("findings sorted CRITICAL → HIGH → MEDIUM → LOW", async () => {
    const result = await scanPath(path.join(FIXTURES, "vulnerable-server-A"));
    const ranks = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 } as const;
    for (let i = 1; i < result.findings.length; i++) {
      const a = result.findings[i - 1];
      const b = result.findings[i];
      if (a && b) {
        expect(ranks[a.severity]).toBeGreaterThanOrEqual(ranks[b.severity]);
      }
    }
  });

  it("vulnerable-server-B has at least one HIGH and one MEDIUM", async () => {
    const result = await scanPath(path.join(FIXTURES, "vulnerable-server-B"));
    expect(result.summary.bySeverity.HIGH).toBeGreaterThanOrEqual(1);
    expect(result.summary.bySeverity.MEDIUM).toBeGreaterThanOrEqual(1);
  });

  it("safe-server has no CRITICAL or HIGH findings", async () => {
    const result = await scanPath(path.join(FIXTURES, "safe-server"));
    expect(result.summary.bySeverity.CRITICAL).toBe(0);
    expect(result.summary.bySeverity.HIGH).toBe(0);
  });

  it("severityFloor=HIGH suppresses LOW and MEDIUM", async () => {
    const result = await scanPath(path.join(FIXTURES, "vulnerable-server-A"), {
      severityFloor: "HIGH",
    });
    expect(result.summary.bySeverity.LOW).toBe(0);
    expect(result.summary.bySeverity.MEDIUM).toBe(0);
    expect(
      result.findings.every(
        (f) => f.severity === "HIGH" || f.severity === "CRITICAL",
      ),
    ).toBe(true);
  });

  it("missing path produces an error entry, not a crash", async () => {
    const result = await scanPath("/nonexistent/path/__shellguard_missing__");
    expect(result.errors.length).toBe(1);
    expect(result.errors[0]?.message).toMatch(/not found/);
    expect(result.findings.length).toBe(0);
  });

  it("relativiseFindings turns absolute paths into cwd-relative", async () => {
    const result = await scanPath(path.join(FIXTURES, "safe-server"));
    const rel = relativiseFindings(result, FIXTURES);
    for (const f of rel.findings) {
      expect(path.isAbsolute(f.file)).toBe(false);
    }
  });
});

describe("scanPath — pragmas", () => {
  it("// shellguard:ignore-file skips the file entirely", async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "sg-test-"));
    const file = path.join(tmp, "ignored.ts");
    await fs.writeFile(
      file,
      [
        "// shellguard:ignore-file",
        "import cp from 'child_process';",
        "declare const cmd: string;",
        "cp.exec(cmd);",
        "",
      ].join("\n"),
      "utf8",
    );
    const result = await scanPath(tmp);
    expect(result.findings.length).toBe(0);
    expect(result.summary.filesSkipped).toBeGreaterThanOrEqual(1);
  });

  it("// shellguard:ignore-next-line suppresses next line only", async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "sg-test-"));
    const file = path.join(tmp, "with-pragma.ts");
    await fs.writeFile(
      file,
      [
        "import child_process from 'child_process';",
        "declare const cmd: string;",
        "// shellguard:ignore-next-line",
        "child_process.exec(cmd);",
        "child_process.exec(cmd);",
        "",
      ].join("\n"),
      "utf8",
    );
    const result = await scanPath(tmp);
    // First exec(cmd) is suppressed, second still fires CRITICAL
    expect(
      result.findings.filter((f) => f.id === "exec_dynamic_string").length,
    ).toBe(1);
  });
});

describe("scanPath — parse errors", () => {
  it("syntactically invalid file lands in errors[]", async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "sg-parse-"));
    const file = path.join(tmp, "broken.ts");
    await fs.writeFile(file, "function (((((( ", "utf8");
    const result = await scanPath(tmp);
    expect(result.errors.length).toBeGreaterThanOrEqual(1);
    expect(result.errors[0]?.message).toMatch(/parse error/);
  });
});
