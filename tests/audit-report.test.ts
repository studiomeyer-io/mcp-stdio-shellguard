import { describe, it, expect } from "vitest";
import path from "node:path";
import { scanPath } from "../src/audit/scanner.js";
import { renderReport } from "../src/audit/report.js";

const FIXTURES = path.resolve(__dirname, "..", "fixtures");

describe("renderReport", () => {
  it("markdown format includes summary and findings table", async () => {
    const result = await scanPath(path.join(FIXTURES, "vulnerable-server-A"));
    const r = renderReport(result, "markdown");
    expect(r.mimeType).toBe("text/markdown");
    expect(r.report).toMatch(/# mcp-shellguard-audit report/);
    expect(r.report).toMatch(/## Summary/);
    expect(r.report).toMatch(/## Findings/);
    expect(r.report).toMatch(/CRITICAL=/);
  });

  it("markdown format reports (none) when no findings", async () => {
    const result = await scanPath(path.join(FIXTURES, "safe-server"));
    const r = renderReport(result, "markdown");
    expect(r.report).toMatch(/\(none\)/);
  });

  it("json format is parseable JSON with findings + summary", async () => {
    const result = await scanPath(path.join(FIXTURES, "vulnerable-server-A"));
    const r = renderReport(result, "json");
    expect(r.mimeType).toBe("application/json");
    const parsed = JSON.parse(r.report) as Record<string, unknown>;
    expect(parsed.findings).toBeDefined();
    expect(parsed.summary).toBeDefined();
    expect(Array.isArray(parsed.findings)).toBe(true);
  });

  it("sarif format is SARIF 2.1.0 schema-compliant skeleton", async () => {
    const result = await scanPath(path.join(FIXTURES, "vulnerable-server-A"));
    const r = renderReport(result, "sarif");
    expect(r.mimeType).toBe("application/sarif+json");
    const parsed = JSON.parse(r.report) as {
      version: string;
      runs: Array<{
        tool: { driver: { name: string; rules: unknown[] } };
        results: Array<{
          ruleId: string;
          level: string;
          message: { text: string };
        }>;
      }>;
    };
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs.length).toBe(1);
    expect(parsed.runs[0]?.tool.driver.name).toBe("mcp-shellguard-audit");
    expect(parsed.runs[0]?.results.length).toBeGreaterThan(0);
    // CRITICAL/HIGH must map to "error" level
    const errorLevels = parsed.runs[0]?.results.filter(
      (r) => r.level === "error",
    );
    expect(errorLevels?.length ?? 0).toBeGreaterThan(0);
  });

  it("sarif level mapping: CRITICAL → error, MEDIUM → warning, LOW → note", async () => {
    const result = await scanPath(path.join(FIXTURES, "vulnerable-server-B"));
    const r = renderReport(result, "sarif");
    const parsed = JSON.parse(r.report) as {
      runs: Array<{
        results: Array<{ level: string; properties: { severity: string } }>;
      }>;
    };
    const results = parsed.runs[0]?.results ?? [];
    for (const res of results) {
      const sev = res.properties.severity;
      if (sev === "CRITICAL" || sev === "HIGH") expect(res.level).toBe("error");
      if (sev === "MEDIUM") expect(res.level).toBe("warning");
      if (sev === "LOW") expect(res.level).toBe("note");
    }
  });
});
