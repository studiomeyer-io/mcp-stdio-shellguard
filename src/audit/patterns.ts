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
  /**
   * Canonical child_process method this call resolves to when the callee
   * is a *renamed* binding the scanner proved originates from
   * child_process (e.g. `execAsync` from `promisify(exec)` resolves to
   * `"exec"`). When set, the rules treat the call as that method even
   * though `callee` is the alias. Purely additive on top of the
   * name-based matching above. See ./bindings.ts.
   */
  resolvedMethod?: string | null;
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

/**
 * True when `call` invokes child_process `method`, via either the
 * name-based matcher (`child_process.exec`, bare `exec`, …) OR a proven
 * alias the binding resolver mapped to `method`. This keeps the original
 * behaviour intact (no finding is lost) while catching renamed bindings.
 */
function callIsMethod(call: AnalysedCall, method: string): boolean {
  if (isChildProcessMethod(call.callee, method)) return true;
  return call.resolvedMethod === method;
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
      // `shell: true` is the obvious case. But Node ALSO runs the command
      // through a shell when `shell` is a non-empty STRING path
      // (`{ shell: "/bin/bash" }` / `{ shell: "cmd.exe" }`), which re-opens
      // the exact string-concatenation attack surface. The cold-cross
      // review of v0.1.1 found the literal-`true`-only check let
      // `spawn(file, args, { shell: "/bin/sh" })` slip through as a mere
      // MEDIUM. Treat any string shell — and any *dynamic* shell value
      // (identifier / member / interpolated template) we cannot prove is
      // falsy — as shell execution.
      if (value.type === "Literal") {
        if (value.value === true) return true;
        if (typeof value.value === "string" && value.value.length > 0) {
          return true;
        }
        // `shell: false` / `shell: ""` / `shell: 0` → not a shell.
        continue;
      }
      if (
        value.type === "Identifier" ||
        value.type === "MemberExpression" ||
        value.type === "TemplateLiteral"
      ) {
        return true;
      }
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
    test: (call) =>
      callIsMethod(call, "exec") &&
      call.args.length >= 1 &&
      call.args[0] !== undefined &&
      templateHasInterpolation(call.args[0]),
  },
  {
    id: "exec_dynamic_string",
    severity: "CRITICAL",
    label: "exec(<dynamic-string>)",
    test: (call) =>
      callIsMethod(call, "exec") &&
      call.args.length >= 1 &&
      call.args[0] !== undefined &&
      !templateHasInterpolation(call.args[0]) &&
      isDynamicString(call.args[0]),
  },
  {
    id: "exec_sync_dynamic_string",
    severity: "CRITICAL",
    label: "execSync(<dynamic-string>)",
    test: (call) =>
      callIsMethod(call, "execSync") &&
      call.args.length >= 1 &&
      call.args[0] !== undefined &&
      isDynamicString(call.args[0]),
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
    // `spawnSync` shares the threat model with `spawn` — the cold-cross
    // review of v0.1.1 found the sync variant was uncovered entirely.
    test: (call) =>
      (callIsMethod(call, "spawn") || callIsMethod(call, "spawnSync")) &&
      call.args.length >= 1 &&
      call.args[0] !== undefined &&
      isDynamicString(call.args[0]) &&
      (call.args.length < 2 ||
        (call.args[1] !== undefined && isDynamicArray(call.args[1]))),
  },
  {
    id: "exec_file_dynamic",
    severity: "HIGH",
    label: "execFile(<dynamic>)",
    // `execFileSync` is the same risk class as `execFile`.
    test: (call) =>
      (callIsMethod(call, "execFile") || callIsMethod(call, "execFileSync")) &&
      call.args.length >= 1 &&
      call.args[0] !== undefined &&
      isDynamicString(call.args[0]),
  },
  {
    id: "shell_true_option",
    severity: "HIGH",
    label: "shell: true",
    test: (call) => {
      if (
        !callIsMethod(call, "spawn") &&
        !callIsMethod(call, "spawnSync") &&
        !callIsMethod(call, "exec") &&
        !callIsMethod(call, "execFile") &&
        !callIsMethod(call, "execFileSync")
      ) {
        return false;
      }
      // Scan ALL ObjectExpression args, not only the last. With
      // `exec(cmd, options, callback)` or
      // `spawn(file, args, options, callback)` the options object is
      // not the final arg, so a "last arg only" check missed
      // `{ shell: true }` whenever a callback was passed. Cold-cross
      // review (S991-Folge) flagged this as HIGH. `objectHasShellTrue`
      // also now catches `{ shell: "/bin/sh" }` (string shell) and any
      // dynamic shell value (v0.1.2 cold-cross follow-up).
      return call.args.some((arg) => objectHasShellTrue(arg));
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
    test: (call) =>
      (callIsMethod(call, "spawn") || callIsMethod(call, "spawnSync")) &&
      call.args.length >= 2 &&
      call.args[0] !== undefined &&
      call.args[1] !== undefined &&
      isLiteralString(call.args[0]) &&
      isDynamicArray(call.args[1]),
  },
  {
    id: "unbounded_buffer",
    severity: "LOW",
    label: "no maxBuffer",
    test: (call) => {
      if (
        !callIsMethod(call, "exec") &&
        !callIsMethod(call, "execFile") &&
        !callIsMethod(call, "execFileSync") &&
        !callIsMethod(call, "execSync")
      ) {
        return false;
      }
      // search for an options object with maxBuffer
      for (const arg of call.args) {
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
    test: (call) => {
      if (
        !callIsMethod(call, "spawn") &&
        !callIsMethod(call, "spawnSync") &&
        !callIsMethod(call, "exec") &&
        !callIsMethod(call, "execFile") &&
        !callIsMethod(call, "execFileSync") &&
        !callIsMethod(call, "execSync")
      ) {
        return false;
      }
      for (const arg of call.args) {
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
 *
 * `resolvedMethod` lets the scanner pass a canonical child_process
 * method name when the callee is a *renamed* binding it proved comes
 * from child_process (see ./bindings.ts). It is optional and purely
 * additive — omitting it preserves the original name-based behaviour.
 */
export function evaluateCall(
  node: TSESTree.CallExpression,
  resolvedMethod?: string | null,
): PatternMatch[] {
  const analysed = analyseCall(node);
  if (resolvedMethod !== undefined && resolvedMethod !== null) {
    analysed.resolvedMethod = resolvedMethod;
  }
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
  isChildProcessMethod,
};
