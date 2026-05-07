import { describe, it, expect } from "vitest";
import { parse } from "@typescript-eslint/parser";
import type { TSESTree } from "@typescript-eslint/types";
import {
  PATTERN_RULES,
  evaluateCall,
  severityAtOrAbove,
  SEVERITY_RANK,
  __test__,
} from "../src/audit/patterns.js";

function firstCall(src: string): TSESTree.CallExpression {
  const ast = parse(src, {
    loc: true,
    range: true,
    ecmaVersion: "latest",
    sourceType: "module",
  });
  let found: TSESTree.CallExpression | null = null;
  function walk(node: TSESTree.Node | null | undefined): void {
    if (!node || found) return;
    if (node.type === "CallExpression") {
      found = node;
      return;
    }
    for (const key of Object.keys(node) as Array<keyof typeof node>) {
      const child = node[key] as unknown;
      if (Array.isArray(child)) {
        for (const c of child) {
          if (c && typeof c === "object" && "type" in c) {
            walk(c as TSESTree.Node);
            if (found) return;
          }
        }
      } else if (child && typeof child === "object" && "type" in child) {
        walk(child as TSESTree.Node);
        if (found) return;
      }
    }
  }
  walk(ast as TSESTree.Node);
  if (!found) throw new Error("no call expression found in: " + src);
  return found;
}

describe("PATTERN_RULES catalogue", () => {
  it("has 12 rules", () => {
    expect(PATTERN_RULES.length).toBe(12);
  });

  it("rule ids are unique", () => {
    const ids = PATTERN_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("severity rank ordered LOW<MEDIUM<HIGH<CRITICAL", () => {
    expect(SEVERITY_RANK.LOW).toBeLessThan(SEVERITY_RANK.MEDIUM);
    expect(SEVERITY_RANK.MEDIUM).toBeLessThan(SEVERITY_RANK.HIGH);
    expect(SEVERITY_RANK.HIGH).toBeLessThan(SEVERITY_RANK.CRITICAL);
  });

  it("severityAtOrAbove gates correctly", () => {
    expect(severityAtOrAbove("HIGH", "MEDIUM")).toBe(true);
    expect(severityAtOrAbove("LOW", "HIGH")).toBe(false);
    expect(severityAtOrAbove("CRITICAL", "CRITICAL")).toBe(true);
  });
});

describe("evaluateCall — CRITICAL patterns", () => {
  it("exec template literal with interpolation", () => {
    const call = firstCall("child_process.exec(`ls ${x}`)");
    const m = evaluateCall(call);
    expect(m.some((x) => x.id === "exec_template_literal_with_input")).toBe(
      true,
    );
  });

  it("exec dynamic string (variable)", () => {
    const call = firstCall("child_process.exec(cmd)");
    const m = evaluateCall(call);
    expect(m.some((x) => x.id === "exec_dynamic_string")).toBe(true);
  });

  it("execSync dynamic string", () => {
    const call = firstCall("child_process.execSync(cmd)");
    const m = evaluateCall(call);
    expect(m.some((x) => x.id === "exec_sync_dynamic_string")).toBe(true);
  });

  it("eval(...)", () => {
    const call = firstCall("eval(payload)");
    const m = evaluateCall(call);
    expect(m.some((x) => x.id === "eval_near_child_process")).toBe(true);
  });

  it("Function(...) constructor", () => {
    const call = firstCall("Function('return 1')()");
    // outer call is Function('return 1')() — inner Function(...) is a CallExpression
    const ast = parse("const x = Function('a', 'return a')();", {
      loc: true,
      range: true,
      ecmaVersion: "latest",
      sourceType: "module",
    });
    let inner: TSESTree.CallExpression | null = null;
    function walk(n: TSESTree.Node): void {
      if (
        n.type === "CallExpression" &&
        n.callee.type === "Identifier" &&
        n.callee.name === "Function"
      ) {
        inner = n;
        return;
      }
      for (const k of Object.keys(n) as Array<keyof typeof n>) {
        const c = n[k] as unknown;
        if (Array.isArray(c)) {
          for (const x of c) {
            if (x && typeof x === "object" && "type" in x)
              walk(x as TSESTree.Node);
          }
        } else if (c && typeof c === "object" && "type" in c) {
          walk(c as TSESTree.Node);
        }
      }
    }
    walk(ast as TSESTree.Node);
    expect(inner).not.toBeNull();
    expect(call).toBeDefined();
    if (inner) {
      const m = evaluateCall(inner);
      expect(
        m.some((x) => x.id === "function_constructor_near_child_process"),
      ).toBe(true);
    }
  });
});

describe("evaluateCall — HIGH patterns", () => {
  it("spawn(<dynamic>, <dynamic-args>)", () => {
    const call = firstCall("child_process.spawn(bin, userArgs)");
    const m = evaluateCall(call);
    expect(m.some((x) => x.id === "spawn_dynamic_file_args")).toBe(true);
  });

  it("execFile(<dynamic>)", () => {
    const call = firstCall("child_process.execFile(bin, [])");
    const m = evaluateCall(call);
    expect(m.some((x) => x.id === "exec_file_dynamic")).toBe(true);
  });

  it("shell: true option", () => {
    const call = firstCall(
      "child_process.spawn('git', ['log'], { shell: true })",
    );
    const m = evaluateCall(call);
    expect(m.some((x) => x.id === "shell_true_option")).toBe(true);
  });

  it("Deno.run is os_system_equivalent", () => {
    const call = firstCall("Deno.run({ cmd: ['ls'] })");
    const m = evaluateCall(call);
    expect(m.some((x) => x.id === "os_system_equivalent")).toBe(true);
  });
});

describe("evaluateCall — MEDIUM and LOW patterns", () => {
  it("spawn(<literal>, <dynamic-args>) is MEDIUM", () => {
    const call = firstCall("child_process.spawn('git', userArgs)");
    const m = evaluateCall(call);
    expect(m.some((x) => x.id === "spawn_literal_dynamic_args")).toBe(true);
  });

  it("exec without maxBuffer fires unbounded_buffer LOW", () => {
    const call = firstCall("child_process.exec('git log', {})");
    const m = evaluateCall(call);
    expect(m.some((x) => x.id === "unbounded_buffer")).toBe(true);
  });

  it("exec with maxBuffer does NOT fire unbounded_buffer", () => {
    const call = firstCall(
      "child_process.exec('git log', { maxBuffer: 1024 * 1024 })",
    );
    const m = evaluateCall(call);
    expect(m.some((x) => x.id === "unbounded_buffer")).toBe(false);
  });

  it("exec without timeout fires missing_timeout LOW", () => {
    const call = firstCall("child_process.exec('git log')");
    const m = evaluateCall(call);
    expect(m.some((x) => x.id === "missing_timeout")).toBe(true);
  });

  it("spawn with timeout does NOT fire missing_timeout", () => {
    const call = firstCall(
      "child_process.spawn('git', ['log'], { timeout: 5000 })",
    );
    const m = evaluateCall(call);
    expect(m.some((x) => x.id === "missing_timeout")).toBe(false);
  });
});

describe("evaluateCall — safe calls", () => {
  it("spawn(literal, literal-array, options-with-timeout-and-maxBuffer-irrelevant) is clean", () => {
    const call = firstCall(
      "child_process.spawn('git', ['log', '--oneline'], { timeout: 5000 })",
    );
    const m = evaluateCall(call);
    // spawn does not need maxBuffer (no exec), so unbounded_buffer should NOT fire
    expect(m.find((x) => x.id === "unbounded_buffer")).toBeUndefined();
    expect(m.find((x) => x.id === "missing_timeout")).toBeUndefined();
    expect(m.find((x) => x.severity === "CRITICAL")).toBeUndefined();
    expect(m.find((x) => x.severity === "HIGH")).toBeUndefined();
  });

  it("non-child-process call does not fire", () => {
    const call = firstCall("console.log('hello')");
    const m = evaluateCall(call);
    expect(m.length).toBe(0);
  });
});

describe("__test__ helpers", () => {
  it("isLiteralString detects literals + empty templates", () => {
    const a = firstCall("f('x')").arguments[0];
    expect(__test__.isLiteralString(a)).toBe(true);
    const b = firstCall("f(`x`)").arguments[0];
    expect(__test__.isLiteralString(b)).toBe(true);
    const c = firstCall("f(`${y}`)").arguments[0];
    expect(__test__.isLiteralString(c)).toBe(false);
  });

  it("templateHasInterpolation only true for ${} templates", () => {
    const a = firstCall("f(`x`)").arguments[0];
    expect(__test__.templateHasInterpolation(a)).toBe(false);
    const b = firstCall("f(`x${y}`)").arguments[0];
    expect(__test__.templateHasInterpolation(b)).toBe(true);
  });

  it("isLiteralArray vs isDynamicArray", () => {
    const a = firstCall("f(['a','b'])").arguments[0];
    expect(__test__.isLiteralArray(a)).toBe(true);
    expect(__test__.isDynamicArray(a)).toBe(false);
    const b = firstCall("f([x, 'b'])").arguments[0];
    expect(__test__.isLiteralArray(b)).toBe(false);
    expect(__test__.isDynamicArray(b)).toBe(true);
    const c = firstCall("f(userArgs)").arguments[0];
    expect(__test__.isDynamicArray(c)).toBe(true);
  });

  it("objectHasShellTrue", () => {
    const a = firstCall("f({ shell: true })").arguments[0];
    expect(__test__.objectHasShellTrue(a)).toBe(true);
    const b = firstCall("f({ shell: false })").arguments[0];
    expect(__test__.objectHasShellTrue(b)).toBe(false);
    const c = firstCall("f({})").arguments[0];
    expect(__test__.objectHasShellTrue(c)).toBe(false);
  });
});
