import { describe, it, expect } from "vitest";
import { AllowlistRegistry } from "../src/guard/allowlist.js";
import { deriveTrustTier } from "../src/guard/tier.js";

describe("deriveTrustTier", () => {
  it("LOW when tool not registered", () => {
    const r = new AllowlistRegistry();
    const t = deriveTrustTier(r, "x", {
      sandboxActive: true,
      replayActive: true,
    });
    expect(t.tier).toBe("LOW");
    expect(t.reasons.join(" ")).toMatch(/not registered/);
    expect(t.improvementHints.length).toBeGreaterThan(0);
  });

  it("MEDIUM when executable registered but no argsPatterns", () => {
    const r = new AllowlistRegistry();
    r.register({ toolName: "t", executable: "/x", argsPatterns: [] });
    const t = deriveTrustTier(r, "t", {
      sandboxActive: true,
      replayActive: true,
    });
    expect(t.tier).toBe("MEDIUM");
  });

  it("HIGH when argsPatterns set but sandbox/replay inactive", () => {
    const r = new AllowlistRegistry();
    r.register({ toolName: "t", executable: "/x", argsPatterns: ["^a$"] });
    const t = deriveTrustTier(r, "t", {
      sandboxActive: false,
      replayActive: false,
    });
    expect(t.tier).toBe("HIGH");
    expect(t.improvementHints.some((h) => h.includes("sandbox"))).toBe(true);
    expect(t.improvementHints.some((h) => h.includes("replay"))).toBe(true);
  });

  it("CRITICAL when args + sandbox + replay all active", () => {
    const r = new AllowlistRegistry();
    r.register({ toolName: "t", executable: "/x", argsPatterns: ["^a$"] });
    const t = deriveTrustTier(r, "t", {
      sandboxActive: true,
      replayActive: true,
    });
    expect(t.tier).toBe("CRITICAL");
    expect(t.improvementHints.length).toBe(0);
  });

  it("HIGH when only sandbox missing", () => {
    const r = new AllowlistRegistry();
    r.register({ toolName: "t", executable: "/x", argsPatterns: ["^a$"] });
    const t = deriveTrustTier(r, "t", {
      sandboxActive: false,
      replayActive: true,
    });
    expect(t.tier).toBe("HIGH");
    expect(t.improvementHints.some((h) => h.includes("sandbox"))).toBe(true);
  });
});
