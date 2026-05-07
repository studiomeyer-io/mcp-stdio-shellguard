import { describe, it, expect } from "vitest";
import path from "node:path";
import { runCli } from "../src/cli.js";

const FIXTURES = path.resolve(__dirname, "..", "fixtures");
const ROOT = path.resolve(__dirname, "..");

interface CapturedRun {
  out: string;
  err: string;
  code: number;
}

async function runCaptured(argv: string[]): Promise<CapturedRun> {
  let out = "";
  let err = "";
  let code = -1;
  await runCli({
    argv,
    cwd: ROOT,
    out: (s) => {
      out += s;
    },
    err: (s) => {
      err += s;
    },
    exit: (c) => {
      code = c;
    },
  });
  return { out, err, code };
}

describe("runCli — exit codes", () => {
  it("exits 0 on safe-server scan", async () => {
    const r = await runCaptured([
      "scan",
      path.relative(ROOT, path.join(FIXTURES, "safe-server")),
    ]);
    expect(r.code).toBe(0);
  });

  it("exits 1 on vulnerable-server-A scan (findings present)", async () => {
    const r = await runCaptured([
      "scan",
      path.relative(ROOT, path.join(FIXTURES, "vulnerable-server-A")),
    ]);
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/CRITICAL/);
  });

  it("exits 2 on missing path", async () => {
    const r = await runCaptured(["scan", "/__definitely_not_a_path__"]);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/warn|not found/);
  });

  it("exits 2 on invalid --severity-floor", async () => {
    const r = await runCaptured([
      "scan",
      path.relative(ROOT, path.join(FIXTURES, "safe-server")),
      "--severity-floor",
      "BANANA",
    ]);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/invalid --severity-floor/);
  });

  it("exits 2 on invalid --format", async () => {
    const r = await runCaptured([
      "scan",
      path.relative(ROOT, path.join(FIXTURES, "safe-server")),
      "--format",
      "xml",
    ]);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/invalid --format/);
  });
});

describe("runCli — formats", () => {
  it("--format json produces parseable JSON", async () => {
    const r = await runCaptured([
      "scan",
      path.relative(ROOT, path.join(FIXTURES, "vulnerable-server-A")),
      "--format",
      "json",
    ]);
    expect(r.code).toBe(1);
    const parsed = JSON.parse(r.out) as { findings: unknown[] };
    expect(Array.isArray(parsed.findings)).toBe(true);
  });

  it("--format sarif produces SARIF 2.1.0", async () => {
    const r = await runCaptured([
      "scan",
      path.relative(ROOT, path.join(FIXTURES, "vulnerable-server-A")),
      "--format",
      "sarif",
    ]);
    expect(r.code).toBe(1);
    const parsed = JSON.parse(r.out) as { version: string };
    expect(parsed.version).toBe("2.1.0");
  });

  it("--severity-floor HIGH suppresses LOW/MEDIUM in output", async () => {
    const r = await runCaptured([
      "scan",
      path.relative(ROOT, path.join(FIXTURES, "vulnerable-server-A")),
      "--severity-floor",
      "HIGH",
      "--format",
      "json",
    ]);
    expect(r.code).toBe(1);
    const parsed = JSON.parse(r.out) as {
      findings: Array<{ severity: string }>;
    };
    expect(
      parsed.findings.every(
        (f) => f.severity === "HIGH" || f.severity === "CRITICAL",
      ),
    ).toBe(true);
  });
});

describe("runCli — version subcommand", () => {
  it("prints version", async () => {
    const r = await runCaptured(["version"]);
    expect(r.code).toBe(0);
    expect(r.out.trim()).toMatch(/\d+\.\d+\.\d+/);
  });
});
