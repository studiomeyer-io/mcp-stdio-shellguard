#!/usr/bin/env node
/**
 * `mcp-shellguard-audit` — commander-based CLI that scans a path for
 * unsanitised child_process calls. Subcommands:
 *
 *   scan <path>   — emit findings (markdown by default)
 *   version       — print package version
 *
 * Exit codes:
 *   0 — clean (no findings at-or-above floor)
 *   1 — findings at-or-above floor (CI gate)
 *   2 — parse / IO errors (false-negative-safe)
 */

import { writeFileSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { Command } from "commander";
import { scanPath, relativiseFindings } from "./audit/scanner.js";
import { renderReport, type ReportFormat } from "./audit/report.js";
import type { AuditSeverity } from "./audit/patterns.js";

function readVersion(): string {
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const candidates = [
      path.resolve(here, "../package.json"),
      path.resolve(here, "../../package.json"),
    ];
    for (const c of candidates) {
      try {
        const pkg = JSON.parse(readFileSync(c, "utf8")) as { version?: string };
        if (pkg.version) return pkg.version;
      } catch {
        // try next
      }
    }
  } catch {
    // fall through
  }
  return "0.0.0-dev";
}

export interface CliRunOptions {
  argv: string[];
  cwd: string;
  out?: (line: string) => void;
  err?: (line: string) => void;
  /** Test seam — return code instead of process.exit. */
  exit?: (code: number) => void;
}

export async function runCli(opts: CliRunOptions): Promise<number> {
  const out =
    opts.out ??
    ((s: string): void => {
      process.stdout.write(s);
    });
  const errOut =
    opts.err ??
    ((s: string): void => {
      process.stderr.write(s);
    });

  const program = new Command();
  program
    .name("mcp-shellguard-audit")
    .description(
      "Scan TypeScript / JavaScript sources for unsanitised child_process " +
        "calls. Closes the Ox-Security MCP stdio-RCE class.",
    )
    .version(readVersion());

  let exitCode = 0;

  program
    .command("scan <path>")
    .description("Scan a file or directory for shell-injection anti-patterns")
    .option(
      "--severity-floor <level>",
      "Only report findings at or above this severity (LOW|MEDIUM|HIGH|CRITICAL)",
      "LOW",
    )
    .option(
      "--format <format>",
      "Output format (markdown|json|sarif)",
      "markdown",
    )
    .option("--output <file>", "Write report to a file instead of stdout")
    .option(
      "--ignore <glob...>",
      "Additional glob(s) to ignore (in addition to node_modules / dist / build)",
    )
    .option(
      "--ignore-file <file>",
      "(reserved for v0.1.1 — not yet honoured) Read additional ignore globs from file",
    )
    .action(
      async (
        scanTarget: string,
        flags: {
          severityFloor: string;
          format: string;
          output?: string;
          ignore?: string[];
          ignoreFile?: string;
        },
      ) => {
        const floor = flags.severityFloor.toUpperCase() as AuditSeverity;
        if (!["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(floor)) {
          errOut(`error: invalid --severity-floor: ${flags.severityFloor}\n`);
          exitCode = 2;
          return;
        }
        const format = flags.format as ReportFormat;
        if (!["markdown", "json", "sarif"].includes(format)) {
          errOut(`error: invalid --format: ${flags.format}\n`);
          exitCode = 2;
          return;
        }
        const absTarget = path.resolve(opts.cwd, scanTarget);
        const result = relativiseFindings(
          await scanPath(absTarget, {
            severityFloor: floor,
            ...(flags.ignore !== undefined ? { ignoreGlobs: flags.ignore } : {}),
          }),
          opts.cwd,
        );
        if (result.errors.length > 0) {
          for (const e of result.errors) {
            errOut(`warn: ${e.file}: ${e.message}\n`);
          }
        }
        const rendered = renderReport(result, format);
        if (flags.output) {
          writeFileSync(path.resolve(opts.cwd, flags.output), rendered.report, "utf8");
          out(`wrote ${flags.output}\n`);
        } else {
          out(rendered.report);
          if (!rendered.report.endsWith("\n")) out("\n");
        }
        if (result.findings.length > 0) {
          exitCode = 1;
        } else if (result.errors.length > 0) {
          exitCode = 2;
        } else {
          exitCode = 0;
        }
      },
    );

  program
    .command("version")
    .description("Print the package version")
    .action(() => {
      out(`${readVersion()}\n`);
    });

  await program.parseAsync(opts.argv, { from: "user" });
  if (opts.exit) opts.exit(exitCode);
  return exitCode;
}

const isMainModule =
  typeof process !== "undefined" &&
  Array.isArray(process.argv) &&
  process.argv[1] !== undefined &&
  /cli\.[mc]?js$/.test(process.argv[1]);

if (isMainModule) {
  runCli({
    argv: process.argv.slice(2),
    cwd: process.cwd(),
  })
    .then((code) => process.exit(code))
    .catch((err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`fatal: ${msg}\n`);
      process.exit(2);
    });
}
