import { describe, it, expect } from "vitest";
import {
  SANDBOX_PROFILES,
  resolveLimits,
  probeCgroupV2,
} from "../src/guard/sandbox.js";

describe("sandbox profiles", () => {
  it("strict has tighter limits than standard", () => {
    expect(SANDBOX_PROFILES.strict.timeoutMs).toBeLessThan(
      SANDBOX_PROFILES.standard.timeoutMs,
    );
    expect(SANDBOX_PROFILES.strict.maxStdoutBytes).toBeLessThan(
      SANDBOX_PROFILES.standard.maxStdoutBytes,
    );
    expect(SANDBOX_PROFILES.strict.fdBudget).toBeLessThan(
      SANDBOX_PROFILES.standard.fdBudget,
    );
  });

  it("standard has tighter limits than permissive", () => {
    expect(SANDBOX_PROFILES.standard.timeoutMs).toBeLessThan(
      SANDBOX_PROFILES.permissive.timeoutMs,
    );
    expect(SANDBOX_PROFILES.standard.maxStdoutBytes).toBeLessThan(
      SANDBOX_PROFILES.permissive.maxStdoutBytes,
    );
  });

  it("resolveLimits returns the right profile", () => {
    expect(resolveLimits("strict")).toBe(SANDBOX_PROFILES.strict);
    expect(resolveLimits("standard")).toBe(SANDBOX_PROFILES.standard);
    expect(resolveLimits("permissive")).toBe(SANDBOX_PROFILES.permissive);
  });

  it("strict and standard have cgroup limits", () => {
    expect(SANDBOX_PROFILES.strict.cgroup).toBeDefined();
    expect(SANDBOX_PROFILES.standard.cgroup).toBeDefined();
  });

  it("permissive has no cgroup limits", () => {
    expect(SANDBOX_PROFILES.permissive.cgroup).toBeUndefined();
  });

  it("probeCgroupV2 returns inactive when path missing", async () => {
    const result = await probeCgroupV2("/nonexistent/path/for/cgroup/test");
    expect(result.active).toBe(false);
    expect(result.reason).toBeDefined();
  });

  it("probeCgroupV2 with a custom fsApi returns inactive when controllers file unreachable", async () => {
    const result = await probeCgroupV2("/sys/fs/cgroup", {
      access: async () => {
        throw new Error("denied");
      },
    });
    expect(result.active).toBe(false);
  });
});
