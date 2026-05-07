/**
 * Audit scanner — walks TypeScript/JavaScript sources via
 * @typescript-eslint/parser, applies PATTERN_RULES per CallExpression,
 * emits AuditFinding[]. Honours `// shellguard:ignore-next-line`
 * inline pragmas.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import fg from "fast-glob";
import { parse } from "@typescript-eslint/parser";
import type { TSESTree } from "@typescript-eslint/types";
import {
  evaluateCall,
  severityAtOrAbove,
  SEVERITY_RANK,
  type AuditFinding,
  type AuditSeverity,
} from "./patterns.js";
import { SUGGESTED_FIX } from "./suggested-fix.js";

export interface AuditScanOptions {
  ignoreGlobs?: string[];
  severityFloor?: AuditSeverity;
  /** File-level cap to keep AST memory bounded. */
  maxFileBytes?: number;
}

export interface AuditScanResult {
  findings: AuditFinding[];
  summary: {
    filesScanned: number;
    filesSkipped: number;
    bySeverity: Record<AuditSeverity, number>;
    durationMs: number;
  };
  errors: Array<{ file: string; message: string }>;
}

const DEFAULT_IGNORE = [
  "**/node_modules/**",
  "**/dist/**",
  "**/build/**",
  "**/coverage/**",
  "**/.git/**",
];

const DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024;

const TARGET_GLOBS = ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.mjs", "**/*.cjs"];

const IGNORE_PRAGMA_LINE = /\/\/\s*shellguard:ignore-next-line/;
const IGNORE_PRAGMA_FILE = /\/\/\s*shellguard:ignore-file/;

function snippetOf(text: string, line: number): string {
  const lines = text.split(/\r?\n/);
  const idx = Math.max(0, line - 1);
  const raw = lines[idx] ?? "";
  return raw.length > 200 ? `${raw.slice(0, 197)}...` : raw;
}

interface IgnoreMap {
  fileLevel: boolean;
  perLine: Set<number>;
}

function buildIgnoreMap(text: string): IgnoreMap {
  const lines = text.split(/\r?\n/);
  const perLine = new Set<number>();
  let fileLevel = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (IGNORE_PRAGMA_FILE.test(line)) {
      fileLevel = true;
    }
    if (IGNORE_PRAGMA_LINE.test(line)) {
      perLine.add(i + 2); // ignore the next line (1-indexed)
    }
  }
  return { fileLevel, perLine };
}

function walk(
  node: TSESTree.Node | null | undefined,
  visit: (n: TSESTree.Node) => void,
): void {
  if (!node || typeof node !== "object" || !("type" in node)) return;
  visit(node);
  for (const key of Object.keys(node)) {
    if (key === "parent" || key === "loc" || key === "range") continue;
    const child = (node as unknown as Record<string, unknown>)[key];
    if (Array.isArray(child)) {
      for (const c of child) {
        if (c && typeof c === "object" && "type" in c) {
          walk(c as TSESTree.Node, visit);
        }
      }
    } else if (child && typeof child === "object" && "type" in child) {
      walk(child as TSESTree.Node, visit);
    }
  }
}

export async function scanPath(
  rootPath: string,
  opts: AuditScanOptions = {},
): Promise<AuditScanResult> {
  const start = Date.now();
  const ignore = [...DEFAULT_IGNORE, ...(opts.ignoreGlobs ?? [])];
  const maxBytes = opts.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const floor: AuditSeverity = opts.severityFloor ?? "LOW";

  const stat = await fs.stat(rootPath).catch(() => null);
  if (!stat) {
    return {
      findings: [],
      summary: {
        filesScanned: 0,
        filesSkipped: 0,
        bySeverity: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
        durationMs: 0,
      },
      errors: [{ file: rootPath, message: "path not found" }],
    };
  }

  let entries: string[];
  if (stat.isFile()) {
    entries = [rootPath];
  } else {
    entries = await fg(TARGET_GLOBS, {
      cwd: rootPath,
      ignore,
      absolute: true,
      onlyFiles: true,
      dot: false,
    });
  }

  const findings: AuditFinding[] = [];
  const errors: Array<{ file: string; message: string }> = [];
  let filesScanned = 0;
  let filesSkipped = 0;

  for (const file of entries) {
    let text: string;
    try {
      const fstat = await fs.stat(file);
      if (fstat.size > maxBytes) {
        filesSkipped++;
        continue;
      }
      text = await fs.readFile(file, "utf8");
    } catch (err) {
      errors.push({ file, message: (err as Error).message });
      continue;
    }

    const ignoreMap = buildIgnoreMap(text);
    if (ignoreMap.fileLevel) {
      filesSkipped++;
      continue;
    }

    let ast: TSESTree.Program;
    try {
      ast = parse(text, {
        loc: true,
        range: true,
        comment: false,
        tokens: false,
        ecmaVersion: "latest",
        sourceType: "module",
        jsx: file.endsWith(".tsx") || file.endsWith(".jsx"),
      }) as TSESTree.Program;
    } catch (err) {
      errors.push({ file, message: `parse error: ${(err as Error).message}` });
      continue;
    }

    filesScanned++;

    walk(ast, (node) => {
      if (node.type !== "CallExpression" && node.type !== "NewExpression")
        return;
      // NewExpression for `new Function(...)` shaped to look like a CallExpression
      const ce =
        node.type === "NewExpression"
          ? ({
              ...node,
              type: "CallExpression",
            } as unknown as TSESTree.CallExpression)
          : (node as TSESTree.CallExpression);
      const matches = evaluateCall(ce);
      if (matches.length === 0) return;
      const line = node.loc?.start.line ?? 0;
      if (ignoreMap.perLine.has(line)) return;
      const column = node.loc?.start.column ?? 0;
      const snippet = snippetOf(text, line);
      for (const match of matches) {
        if (!severityAtOrAbove(match.severity, floor)) continue;
        findings.push({
          id: match.id,
          severity: match.severity,
          file,
          line,
          column,
          snippet,
          suggestedFix: SUGGESTED_FIX[match.id],
        });
      }
    });
  }

  const bySeverity: Record<AuditSeverity, number> = {
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0,
    CRITICAL: 0,
  };
  for (const f of findings) bySeverity[f.severity]++;

  // sort findings by severity (high → low), then by file/line
  findings.sort((a, b) => {
    const s = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (s !== 0) return s;
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    return a.line - b.line;
  });

  return {
    findings,
    summary: {
      filesScanned,
      filesSkipped,
      bySeverity,
      durationMs: Date.now() - start,
    },
    errors,
  };
}

export function relativiseFindings(
  result: AuditScanResult,
  cwd: string,
): AuditScanResult {
  return {
    ...result,
    findings: result.findings.map((f) => ({
      ...f,
      file: path.relative(cwd, f.file) || f.file,
    })),
  };
}
