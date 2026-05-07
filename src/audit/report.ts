/**
 * Audit-report emitters: markdown, json, sarif (2.1.0). All take an
 * AuditScanResult and return a string + mime type the CLI / MCP tool
 * can ship to disk or stdout.
 */

import type { AuditScanResult } from "./scanner.js";
import type { AuditFinding } from "./patterns.js";

export type ReportFormat = "markdown" | "json" | "sarif";

export interface RenderedReport {
  report: string;
  mimeType: string;
}

export function renderReport(
  result: AuditScanResult,
  format: ReportFormat,
): RenderedReport {
  switch (format) {
    case "markdown":
      return { report: renderMarkdown(result), mimeType: "text/markdown" };
    case "json":
      return {
        report: JSON.stringify(result, null, 2),
        mimeType: "application/json",
      };
    case "sarif":
      return {
        report: JSON.stringify(renderSarif(result), null, 2),
        mimeType: "application/sarif+json",
      };
    default: {
      const exhaustive: never = format;
      throw new Error(`unknown format: ${exhaustive as string}`);
    }
  }
}

function renderMarkdown(result: AuditScanResult): string {
  const lines: string[] = [];
  lines.push("# mcp-shellguard-audit report");
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(`- Files scanned: ${result.summary.filesScanned}`);
  lines.push(`- Files skipped: ${result.summary.filesSkipped}`);
  lines.push(`- Duration: ${result.summary.durationMs} ms`);
  lines.push(
    `- Findings: CRITICAL=${result.summary.bySeverity.CRITICAL} ` +
      `HIGH=${result.summary.bySeverity.HIGH} ` +
      `MEDIUM=${result.summary.bySeverity.MEDIUM} ` +
      `LOW=${result.summary.bySeverity.LOW}`,
  );
  if (result.errors.length > 0) {
    lines.push("");
    lines.push("## Parse / IO errors");
    lines.push("");
    for (const err of result.errors) {
      lines.push(`- \`${err.file}\` — ${err.message}`);
    }
  }
  lines.push("");
  lines.push("## Findings");
  lines.push("");
  if (result.findings.length === 0) {
    lines.push("(none)");
    lines.push("");
    return lines.join("\n");
  }
  lines.push("| Severity | Pattern | File | Line | Suggested fix |");
  lines.push("|----------|---------|------|------|---------------|");
  for (const f of result.findings) {
    lines.push(
      `| ${f.severity} | \`${f.id}\` | \`${f.file}\` | ${f.line} | ${f.suggestedFix.replace(/\|/g, "\\|")} |`,
    );
  }
  lines.push("");
  return lines.join("\n");
}

function renderSarif(result: AuditScanResult): unknown {
  // SARIF 2.1.0 — minimal but valid
  const ruleIds = new Set<string>();
  for (const f of result.findings) ruleIds.add(f.id);
  const rules = [...ruleIds].map((id) => ({
    id,
    name: id,
    shortDescription: { text: id },
    fullDescription: {
      text: result.findings.find((f) => f.id === id)?.suggestedFix ?? id,
    },
    helpUri:
      "https://github.com/studiomeyer-io/mcp-stdio-shellguard#audit-patterns",
  }));
  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-shellguard-audit",
            informationUri:
              "https://github.com/studiomeyer-io/mcp-stdio-shellguard",
            rules,
          },
        },
        results: result.findings.map((f) => mapFindingToSarif(f)),
      },
    ],
  };
}

function mapFindingToSarif(f: AuditFinding): unknown {
  return {
    ruleId: f.id,
    level: sarifLevel(f.severity),
    message: { text: `${f.id}: ${f.suggestedFix}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file },
          region: {
            startLine: f.line,
            startColumn: f.column + 1,
            snippet: { text: f.snippet },
          },
        },
      },
    ],
    properties: { severity: f.severity },
  };
}

function sarifLevel(severity: AuditFinding["severity"]): string {
  switch (severity) {
    case "CRITICAL":
    case "HIGH":
      return "error";
    case "MEDIUM":
      return "warning";
    case "LOW":
      return "note";
  }
}
