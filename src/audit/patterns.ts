/**
 * 12 AST patterns the audit scanner walks for. Each pattern carries a
 * stable id, a severity tier, the matcher predicate (over the AST
 * node) and a suggested-fix key. Patterns are pure functions over the
 * @typescript-eslint/parser AST; the scanner.ts walker calls them on
 * each `CallExpression` / `MemberExpression` it encounters.
 *
 * Source of truth for the threat catalogue: Ox-Security MCP audit
 * (venturebeat 2026-05-02), LiteLLM CVE patched in v1.83.7, plus the
 * `mcp-anti-patterns` Memory entity (#6 shell:true, #11 template-literal).
 */

import type { TSESTree } from "@typescript-eslint/types";
import type { AuditPatternId } from "./suggested-fix.js";

export type AuditSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface AuditFinding {
  id: AuditPatternId;
  severity: AuditSeverity;
  file: string;
  line: number;
  column: number;
  snippet: string;
  suggestedFix: string;
}

export interface PatternMatch {
  id: AuditPatternId;
  severity: AuditSeverity;
  /** Short label rendered in markdown reports. */
  label: string;
}

const CHILD_PROCESS_OBJECT_NAMES = new Set([
  "child_process",
  "cp",
  "childProcess",
]);

interface AnalysedCall {
  /** Final dotted-name like `child_process.exec` if resolvable. */
  callee: string | null;
  args: TSESTree.CallExpressionArgument[];
}

function getCalleeName(node: TSESTree.CallExpression): string | null {
  const callee = node.callee;
  if (callee.type === "Identifier") {
    return callee.name;
  }
  if (callee.type === "MemberExpression" && !callee.computed) {
    const obj = callee.object;
    const prop = callee.property;
    if (obj.type === "Identifier" && prop.type === "Identifier") {
      return `${obj.name}.${prop.name}`;
    }
  }
  return null;
}

function isChildProcessMethod(name: string | null, method: string): boolean {
  if (!name) return false;
  if (name === method) return true;
  const dot = name.indexOf(".");
  if (dot === -1) return false;
  const obj = name.slice(0, dot);
  const m = name.slice(dot + 1);
  return CHILD_PROCESS_OBJECT_NAMES.has(obj) && m === method;
}

function analyseCall(node: TSESTree.CallExpression): AnalysedCall {
  return { callee: getCalleeName(node), args: [...node.arguments] };
}

function isLiteralString(node: TSESTree.Node | undefined): boolean {
  if (!node) return false;
  if (node.type === "Literal" && typeof node.value === "string") return true;
  if (node.type === "TemplateLiteral" && node.expressions.length === 0)
    return true;
  return false;
}

function isDynamicString(node: TSESTree.Node | undefined): boolean {
  if (!node) return false;
  if (node.type === "Literal" && typeof node.value === "string") return false;
  if (node.type === "TemplateLiteral" && node.expressions.length === 0)
    return false;
  return true;
}

function templateHasInterpolation(node: TSESTree.Node | undefined): boolean {
  if (!node) return false;
  return node.type === "TemplateLiteral" && node.expressions.length > 0;
}

function isLiteralArray(node: TSESTree.Node | undefined): boolean {
  if (!node) return false;
  if (node.type !== "ArrayExpression") return false;
  return node.elements.every(
    (el) => el !== null && el.type !== "SpreadElement" && isLiteralString(el),
  );
}

function isDynamicArray(node: TSESTree.Node | undefined): boolean {
  if (!node) return false;
  if (node.type !== "ArrayExpression") return true; // any non-array passed as args is dynamic
  return !isLiteralArray(node);
}

function objectHasShellTrue(node: TSESTree.Node | undefined): boolean {
  if (!node || node.type !== "ObjectExpression") return false;
  for (const prop of node.properties) {
    if (prop.type !== "Property" || prop.computed) continue;
    const key = prop.key;
    if (key.type === "Identifier" && key.name === "shell") {
      const value = prop.value;
      if (value.type === "Literal" && value.value === true) return true;
    }
  }
  return false;
}

export interface PatternRule {
  id: AuditPatternId;
  severity: AuditSeverity;
  label: string;
  /**
   * Inspect a CallExpression and decide whether this rule fires. A
   * single rule can fire only once per call.
   */
  test(call: AnalysedCall): boolean;
}

export const PATTERN_RULES: readonly PatternRule[] = [
  {
    id: "exec_template_literal_with_input",
    severity: "CRITICAL",
    label: "exec(`...${userInput}...`)",
    test: ({ callee, args }) =>
      isChildProcessMethod(callee, "exec") &&
      args.length >= 1 &&
      args[0] !== undefined &&
      templateHasInterpolation(args[0]),
  },
  {
    id: "exec_dynamic_string",
    severity: "CRITICAL",
    label: "exec(<dynamic-string>)",
    test: ({ callee, args }) =>
      isChildProcessMethod(callee, "exec") &&
      args.length >= 1 &&
      args[0] !== undefined &&
      !templateHasInterpolation(args[0]) &&
      isDynamicString(args[0]),
  },
  {
    id: "exec_sync_dynamic_string",
    severity: "CRITICAL",
    label: "execSync(<dynamic-string>)",
    test: ({ callee, args }) =>
      isChildProcessMethod(callee, "execSync") &&
      args.length >= 1 &&
      args[0] !== undefined &&
      isDynamicString(args[0]),
  },
  {
    id: "eval_near_child_process",
    severity: "CRITICAL",
    label: "eval(...)",
    test: ({ callee }) => callee === "eval",
  },
  {
    id: "function_constructor_near_child_process",
    severity: "CRITICAL",
    label: "new Function(...)",
    // matches Function() calls — `new Function` parses as NewExpression
    // but ESTree also allows direct Function() invocation.
    test: ({ callee }) => callee === "Function",
  },
  {
    id: "spawn_dynamic_file_args",
    severity: "HIGH",
    label: "spawn(<dynamic>, <dynamic-args>)",
    test: ({ callee, args }) =>
      isChildProcessMethod(callee, "spawn") &&
      args.length >= 1 &&
      args[0] !== undefined &&
      isDynamicString(args[0]) &&
      (args.length < 2 || (args[1] !== undefined && isDynamicArray(args[1]))),
  },
  {
    id: "exec_file_dynamic",
    severity: "HIGH",
    label: "execFile(<dynamic>)",
    test: ({ callee, args }) =>
      isChildProcessMethod(callee, "execFile") &&
      args.length >= 1 &&
      args[0] !== undefined &&
      isDynamicString(args[0]),
  },
  {
    id: "shell_true_option",
    severity: "HIGH",
    label: "shell: true",
    test: ({ callee, args }) => {
      if (
        !isChildProcessMethod(callee, "spawn") &&
        !isChildProcessMethod(callee, "exec") &&
        !isChildProcessMethod(callee, "execFile")
      ) {
        return false;
      }
      // Scan ALL ObjectExpression args, not only the last. With
      // `exec(cmd, options, callback)` or
      // `spawn(file, args, options, callback)` the options object is
      // not the final arg, so a "last arg only" check missed
      // `{ shell: true }` whenever a callback was passed. Cold-cross
      // review (S991-Folge) flagged this as HIGH.
      return args.some((arg) => objectHasShellTrue(arg));
    },
  },
  {
    id: "os_system_equivalent",
    severity: "HIGH",
    label: "Deno.run / Bun.spawn",
    test: ({ callee }) =>
      callee === "Deno.run" ||
      callee === "Bun.spawn" ||
      callee === "Bun.spawnSync",
  },
  {
    id: "spawn_literal_dynamic_args",
    severity: "MEDIUM",
    label: "spawn(<literal>, <dynamic-args>)",
    test: ({ callee, args }) =>
      isChildProcessMethod(callee, "spawn") &&
      args.length >= 2 &&
      args[0] !== undefined &&
      args[1] !== undefined &&
      isLiteralString(args[0]) &&
      isDynamicArray(args[1]),
  },
  {
    id: "unbounded_buffer",
    severity: "LOW",
    label: "no maxBuffer",
    test: ({ callee, args }) => {
      if (
        !isChildProcessMethod(callee, "exec") &&
        !isChildProcessMethod(callee, "execFile") &&
        !isChildProcessMethod(callee, "execSync")
      ) {
        return false;
      }
      // search for an options object with maxBuffer
      for (const arg of args) {
        if (arg.type === "ObjectExpression") {
          for (const prop of arg.properties) {
            if (
              prop.type === "Property" &&
              !prop.computed &&
              prop.key.type === "Identifier" &&
              prop.key.name === "maxBuffer"
            ) {
              return false;
            }
          }
        }
      }
      return true;
    },
  },
  {
    id: "missing_timeout",
    severity: "LOW",
    label: "no timeout",
    test: ({ callee, args }) => {
      if (
        !isChildProcessMethod(callee, "spawn") &&
        !isChildProcessMethod(callee, "exec") &&
        !isChildProcessMethod(callee, "execFile") &&
        !isChildProcessMethod(callee, "execSync")
      ) {
        return false;
      }
      for (const arg of args) {
        if (arg.type === "ObjectExpression") {
          for (const prop of arg.properties) {
            if (
              prop.type === "Property" &&
              !prop.computed &&
              prop.key.type === "Identifier" &&
              prop.key.name === "timeout"
            ) {
              return false;
            }
          }
        }
      }
      return true;
    },
  },
];

export const SEVERITY_RANK: Record<AuditSeverity, number> = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
  CRITICAL: 3,
};

export function severityAtOrAbove(
  finding: AuditSeverity,
  floor: AuditSeverity,
): boolean {
  return SEVERITY_RANK[finding] >= SEVERITY_RANK[floor];
}

/**
 * Apply rules to one CallExpression. Each rule is at most fired once
 * per call, but a single call may match multiple rules (e.g. dynamic
 * exec + missing timeout). The caller gets the union.
 */
export function evaluateCall(node: TSESTree.CallExpression): PatternMatch[] {
  const analysed = analyseCall(node);
  const matches: PatternMatch[] = [];
  for (const rule of PATTERN_RULES) {
    if (rule.test(analysed)) {
      matches.push({ id: rule.id, severity: rule.severity, label: rule.label });
    }
  }
  return matches;
}

export const __test__ = {
  isLiteralString,
  isDynamicString,
  templateHasInterpolation,
  isLiteralArray,
  isDynamicArray,
  objectHasShellTrue,
};
