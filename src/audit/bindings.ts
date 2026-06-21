/**
 * Whole-program binding resolver for the audit scanner.
 *
 * The per-call pattern matchers in `patterns.ts` only see one
 * `CallExpression` in isolation. That misses the most common real-world
 * shape of the Ox-Security stdio-RCE class: a `child_process` member is
 * bound to a *renamed* local and then called through that local, so the
 * dotted callee name no longer contains `child_process` / `exec`.
 *
 * The cold-cross review of v0.1.1 found four false-negative shapes that
 * the name-only matcher silently passes:
 *
 *   1. `const execAsync = promisify(exec); execAsync(`ls ${x}`)`
 *      — promisify(exec) is THE canonical way MCP servers `await` exec.
 *   2. `import cp from "node:child_process"; cp.exec(`ls ${x}`)`
 *      via a default/namespace import bound to an arbitrary local name.
 *   3. `const { exec: sh } = require("child_process"); sh(`ls ${x}`)`
 *      — destructure-rename off `require`.
 *   4. `import { exec as run } from "node:child_process"; run(`ls ${x}`)`
 *      — named-import alias.
 *
 * This module runs a single pre-pass over the AST, resolves every local
 * identifier (and object member) that provably originates from
 * `child_process` to its canonical method name, and lets the scanner
 * rewrite a call's callee to that canonical name before the rules run.
 *
 * Conservatism is the whole point of a security audit: the resolver only
 * ever maps bindings whose origin is *proven* to be `child_process`
 * (an import from `node:child_process` / `child_process`, or a
 * `require("child_process")`). It never guesses. Resolution is purely
 * *additive* — the name-based matching in `patterns.ts` is left intact,
 * so a binding the resolver cannot prove is simply matched the old way.
 * That guarantees the layer cannot introduce a false negative relative
 * to the previous behaviour, and the only new findings are real aliases.
 */

import type { TSESTree } from "@typescript-eslint/types";

/** Module specifiers that denote Node's child_process. */
const CHILD_PROCESS_SOURCES = new Set(["child_process", "node:child_process"]);

/** Specifiers that denote `node:util` (for promisify resolution). */
const UTIL_SOURCES = new Set(["util", "node:util"]);

/**
 * Methods we care about. Anything not in this set is irrelevant to the
 * threat model and is never recorded, keeping the binding map small.
 */
const CHILD_PROCESS_METHODS = new Set([
  "exec",
  "execSync",
  "execFile",
  "execFileSync",
  "spawn",
  "spawnSync",
]);

export interface BindingResolution {
  /**
   * Local identifier name → canonical child_process method
   * (e.g. `sh` → `exec`). A call `sh(...)` is then treated as
   * `child_process.exec(...)`.
   */
  identifierToMethod: Map<string, string>;
  /**
   * Local identifier name → it is a child_process namespace/default
   * binding (e.g. `cp` from `import cp from "node:child_process"`), so
   * `cp.exec(...)` resolves to the `exec` method.
   */
  namespaceLocals: Set<string>;
  /** Local names bound to `promisify` (bare or via `util.promisify`). */
  promisifyLocals: Set<string>;
  /** Local names bound to a `util` namespace (for `util.promisify`). */
  utilLocals: Set<string>;
}

function literalSource(node: TSESTree.Node | null | undefined): string | null {
  if (node && node.type === "Literal" && typeof node.value === "string") {
    return node.value;
  }
  return null;
}

/**
 * True if `node` is a `require("child_process")` call expression.
 */
function isRequireOf(
  node: TSESTree.Node | null | undefined,
  sources: Set<string>,
): boolean {
  if (!node || node.type !== "CallExpression") return false;
  if (node.callee.type !== "Identifier" || node.callee.name !== "require") {
    return false;
  }
  const arg = node.arguments[0];
  const src = literalSource(arg);
  return src !== null && sources.has(src);
}

function recordImportDeclaration(
  decl: TSESTree.ImportDeclaration,
  out: BindingResolution,
): void {
  const src = literalSource(decl.source);
  if (src === null) return;
  const isCp = CHILD_PROCESS_SOURCES.has(src);
  const isUtil = UTIL_SOURCES.has(src);
  if (!isCp && !isUtil) return;

  for (const spec of decl.specifiers) {
    if (spec.type === "ImportSpecifier") {
      const importedName =
        spec.imported.type === "Identifier" ? spec.imported.name : null;
      const localName = spec.local.name;
      if (importedName === null) continue;
      if (isCp && CHILD_PROCESS_METHODS.has(importedName)) {
        out.identifierToMethod.set(localName, importedName);
      } else if (isUtil && importedName === "promisify") {
        out.promisifyLocals.add(localName);
      }
    } else if (
      spec.type === "ImportDefaultSpecifier" ||
      spec.type === "ImportNamespaceSpecifier"
    ) {
      if (isCp) out.namespaceLocals.add(spec.local.name);
      else if (isUtil) out.utilLocals.add(spec.local.name);
    }
  }
}

/**
 * True when the call is `promisify(<arg>)` or `<util>.promisify(<arg>)`
 * where the resolver knows the promisify binding.
 */
function isPromisifyCall(
  node: TSESTree.CallExpression,
  out: BindingResolution,
): boolean {
  const callee = node.callee;
  if (callee.type === "Identifier") {
    return out.promisifyLocals.has(callee.name);
  }
  if (
    callee.type === "MemberExpression" &&
    !callee.computed &&
    callee.object.type === "Identifier" &&
    callee.property.type === "Identifier" &&
    callee.property.name === "promisify"
  ) {
    // `util.promisify(...)` — accept either a tracked util-local or the
    // bare global `util` identifier (common when util is required whole).
    return out.utilLocals.has(callee.object.name) || callee.object.name === "util";
  }
  return false;
}

/**
 * Resolve the child_process method that `arg` refers to, if any. Handles
 * a bare identifier (`exec`) and a member (`cp.exec`).
 */
function resolveMethodOfExpression(
  arg: TSESTree.Node | null | undefined,
  out: BindingResolution,
): string | null {
  if (!arg) return null;
  if (arg.type === "Identifier") {
    return out.identifierToMethod.get(arg.name) ?? null;
  }
  if (
    arg.type === "MemberExpression" &&
    !arg.computed &&
    arg.object.type === "Identifier" &&
    arg.property.type === "Identifier" &&
    out.namespaceLocals.has(arg.object.name) &&
    CHILD_PROCESS_METHODS.has(arg.property.name)
  ) {
    return arg.property.name;
  }
  return null;
}

function recordVariableDeclarator(
  decl: TSESTree.VariableDeclarator,
  out: BindingResolution,
): void {
  const init = decl.init;
  if (!init) return;

  // const cp = require("child_process")  → namespace local
  // const util = require("util")         → util local
  if (init.type === "CallExpression") {
    if (isRequireOf(init, CHILD_PROCESS_SOURCES) && decl.id.type === "Identifier") {
      out.namespaceLocals.add(decl.id.name);
      return;
    }
    if (isRequireOf(init, UTIL_SOURCES) && decl.id.type === "Identifier") {
      out.utilLocals.add(decl.id.name);
      return;
    }
    // const { exec: sh } = require("child_process")
    if (isRequireOf(init, CHILD_PROCESS_SOURCES) && decl.id.type === "ObjectPattern") {
      recordObjectPattern(decl.id, out);
      return;
    }
    if (isRequireOf(init, UTIL_SOURCES) && decl.id.type === "ObjectPattern") {
      for (const prop of decl.id.properties) {
        if (
          prop.type === "Property" &&
          !prop.computed &&
          prop.key.type === "Identifier" &&
          prop.key.name === "promisify" &&
          prop.value.type === "Identifier"
        ) {
          out.promisifyLocals.add(prop.value.name);
        }
      }
      return;
    }
    // const execAsync = promisify(exec)  /  util.promisify(cp.exec)
    if (isPromisifyCall(init, out) && decl.id.type === "Identifier") {
      const method = resolveMethodOfExpression(init.arguments[0], out);
      if (method !== null) {
        out.identifierToMethod.set(decl.id.name, method);
      }
    }
  }
}

function recordObjectPattern(
  pattern: TSESTree.ObjectPattern,
  out: BindingResolution,
): void {
  for (const prop of pattern.properties) {
    if (prop.type !== "Property" || prop.computed) continue;
    if (prop.key.type !== "Identifier") continue;
    if (!CHILD_PROCESS_METHODS.has(prop.key.name)) continue;
    if (prop.value.type === "Identifier") {
      out.identifierToMethod.set(prop.value.name, prop.key.name);
    }
  }
}

/**
 * Pre-pass: walk the whole program collecting child_process bindings.
 *
 * Two ordered passes so that `const ea = promisify(exec)` resolves even
 * when the `exec` import / require appears anywhere in the file: pass 1
 * records imports + require bindings + promisify locals; pass 2 records
 * promisify-derived locals once the method bindings are known.
 */
export function resolveBindings(program: TSESTree.Node): BindingResolution {
  const out: BindingResolution = {
    identifierToMethod: new Map(),
    namespaceLocals: new Set(),
    promisifyLocals: new Set(),
    utilLocals: new Set(),
  };

  // Pass 1: imports + direct require destructures + promisify locals.
  walkShallow(program, (node) => {
    if (node.type === "ImportDeclaration") {
      recordImportDeclaration(node, out);
    } else if (node.type === "VariableDeclaration") {
      for (const d of node.declarations) {
        const init = d.init;
        if (
          init &&
          init.type === "CallExpression" &&
          (isRequireOf(init, CHILD_PROCESS_SOURCES) ||
            isRequireOf(init, UTIL_SOURCES))
        ) {
          recordVariableDeclarator(d, out);
        }
      }
    }
  });

  // Pass 2: promisify(...) derived locals (need method bindings first).
  walkShallow(program, (node) => {
    if (node.type !== "VariableDeclaration") return;
    for (const d of node.declarations) {
      const init = d.init;
      if (init && init.type === "CallExpression" && isPromisifyCall(init, out)) {
        recordVariableDeclarator(d, out);
      }
    }
  });

  return out;
}

/**
 * Resolve the canonical child_process method for a call, using the
 * binding map. Returns null when the call is not a *resolvable alias*
 * (in which case the name-based matcher in patterns.ts still applies).
 */
export function resolveCallMethod(
  node: TSESTree.CallExpression,
  bindings: BindingResolution,
): string | null {
  const callee = node.callee;
  if (callee.type === "Identifier") {
    return bindings.identifierToMethod.get(callee.name) ?? null;
  }
  if (
    callee.type === "MemberExpression" &&
    !callee.computed &&
    callee.object.type === "Identifier" &&
    callee.property.type === "Identifier" &&
    bindings.namespaceLocals.has(callee.object.name) &&
    CHILD_PROCESS_METHODS.has(callee.property.name)
  ) {
    return callee.property.name;
  }
  return null;
}

/**
 * Minimal whole-tree walker used by the binding pre-pass. Kept local so
 * the resolver has no dependency on scanner.ts.
 */
function walkShallow(
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
          walkShallow(c as TSESTree.Node, visit);
        }
      }
    } else if (child && typeof child === "object" && "type" in child) {
      walkShallow(child as TSESTree.Node, visit);
    }
  }
}

export const __test__ = {
  isRequireOf,
  resolveMethodOfExpression,
  CHILD_PROCESS_METHODS,
};
