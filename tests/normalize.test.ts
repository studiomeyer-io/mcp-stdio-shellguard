import { describe, it, expect } from "vitest";
import {
  normalizeForMatching,
  containsUnicodeWhitespace,
} from "../src/guard/normalize.js";

describe("normalizeForMatching", () => {
  it("returns the empty string unchanged", () => {
    expect(normalizeForMatching("")).toBe("");
  });

  it("leaves benign ASCII unchanged", () => {
    expect(normalizeForMatching("log")).toBe("log");
    expect(normalizeForMatching("--oneline")).toBe("--oneline");
    expect(normalizeForMatching("/usr/bin/git")).toBe("/usr/bin/git");
  });

  it("strips zero-width chars in the middle of a token", () => {
    expect(normalizeForMatching("lo​g")).toBe("log");
    expect(normalizeForMatching("lo‌g")).toBe("log");
    expect(normalizeForMatching("lo‍g")).toBe("log");
  });

  it("strips BOM (U+FEFF) wherever it appears", () => {
    expect(normalizeForMatching("﻿log")).toBe("log");
    expect(normalizeForMatching("log﻿")).toBe("log");
    expect(normalizeForMatching("lo﻿g")).toBe("log");
  });

  it("strips bidi formatting overrides", () => {
    // U+202E RIGHT-TO-LEFT OVERRIDE (Trojan-Source class)
    expect(normalizeForMatching("‮log‬")).toBe("log");
    // U+2066 LEFT-TO-RIGHT ISOLATE
    expect(normalizeForMatching("⁦log⁩")).toBe("log");
  });

  it("strips invisible math operators (U+2061-2064)", () => {
    expect(normalizeForMatching("lo⁢g")).toBe("log");
  });

  it("strips line + paragraph separators (U+2028, U+2029)", () => {
    expect(normalizeForMatching("lo g")).toBe("log");
    expect(normalizeForMatching("lo g")).toBe("log");
  });

  it("collapses fullwidth letters to ASCII via NFKC", () => {
    // FULLWIDTH LATIN SMALL LETTER L/O/G
    expect(normalizeForMatching("ｌｏｇ")).toBe("log");
    // FULLWIDTH HYPHEN-MINUS twice + LATIN ONELINE
    expect(normalizeForMatching("－－oneline")).toBe("--oneline");
  });

  it("collapses fullwidth dollar + parens (the shell-injection hook)", () => {
    // ＄（rm　-rf　/） — fullwidth $, parens, and ideographic spaces
    // The dollar + parens collapse via NFKC; the ideographic spaces
    // do NOT collapse (NFKC keeps them as U+3000) but they are caught
    // separately by containsUnicodeWhitespace at the exec/spawn layer.
    const fullwidth = "＄（rm　-rf　/）";
    const out = normalizeForMatching(fullwidth);
    expect(out).toContain("$");
    expect(out).toContain("(");
    expect(out).toContain(")");
  });

  it("is idempotent", () => {
    const inputs = [
      "log",
      "lo​g",
      "ｌｏｇ",
      "/usr/bin/git",
    ];
    for (const s of inputs) {
      expect(normalizeForMatching(normalizeForMatching(s))).toBe(
        normalizeForMatching(s),
      );
    }
  });

  it("non-string inputs return as-is (defensive)", () => {
    expect(normalizeForMatching(undefined as unknown as string)).toBe(undefined);
    expect(normalizeForMatching(null as unknown as string)).toBe(null);
    expect(normalizeForMatching(42 as unknown as string)).toBe(42);
  });
});

describe("containsUnicodeWhitespace", () => {
  it("returns false for empty string", () => {
    expect(containsUnicodeWhitespace("")).toBe(false);
  });

  it("returns false for a clean ASCII path", () => {
    expect(containsUnicodeWhitespace("/usr/bin/git")).toBe(false);
    expect(containsUnicodeWhitespace("log")).toBe(false);
  });

  it("catches ASCII space (regression of original includes-check)", () => {
    expect(containsUnicodeWhitespace("/usr/bin/sh -c")).toBe(true);
  });

  it("catches ASCII tab + newline + carriage return", () => {
    expect(containsUnicodeWhitespace("a\tb")).toBe(true);
    expect(containsUnicodeWhitespace("a\nb")).toBe(true);
    expect(containsUnicodeWhitespace("a\rb")).toBe(true);
  });

  it("catches U+00A0 NO-BREAK SPACE", () => {
    expect(containsUnicodeWhitespace("a b")).toBe(true);
  });

  it("catches U+3000 IDEOGRAPHIC SPACE (CJK fullwidth)", () => {
    expect(containsUnicodeWhitespace("/usr/bin/git　--exec")).toBe(true);
  });

  it("catches general-punctuation whitespace block", () => {
    expect(containsUnicodeWhitespace("a b")).toBe(true); // EN SPACE
    expect(containsUnicodeWhitespace("a b")).toBe(true); // THIN SPACE
    expect(containsUnicodeWhitespace("a b")).toBe(true); // HAIR SPACE
  });

  it("catches U+202F NARROW NO-BREAK SPACE + U+205F", () => {
    expect(containsUnicodeWhitespace("a b")).toBe(true);
    expect(containsUnicodeWhitespace("a b")).toBe(true);
  });

  it("catches U+1680 OGHAM SPACE MARK", () => {
    expect(containsUnicodeWhitespace("a b")).toBe(true);
  });

  it("catches U+FEFF BOM", () => {
    expect(containsUnicodeWhitespace("a﻿b")).toBe(true);
  });

  it("non-string inputs return false (defensive)", () => {
    expect(
      containsUnicodeWhitespace(undefined as unknown as string),
    ).toBe(false);
    expect(containsUnicodeWhitespace(null as unknown as string)).toBe(false);
  });
});
