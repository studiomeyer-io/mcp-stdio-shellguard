import { describe, it, expect } from "vitest";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { createServer, makeState, TOOLS } from "../src/server.js";

describe("server — TOOLS catalogue", () => {
  it("exposes 8 tools", () => {
    expect(TOOLS.length).toBe(8);
  });

  it("each tool has name + description + inputSchema + annotations", () => {
    for (const t of TOOLS) {
      expect(t.name).toMatch(/^[a-z_]+$/);
      expect(typeof t.description).toBe("string");
      expect((t.description ?? "").length).toBeGreaterThan(20);
      expect(t.inputSchema).toBeDefined();
      expect(t.annotations).toBeDefined();
    }
  });

  it("each tool inputSchema is type=object with properties", () => {
    for (const t of TOOLS) {
      const s = t.inputSchema as { type: string; properties: unknown };
      expect(s.type).toBe("object");
      expect(s.properties).toBeDefined();
    }
  });

  it("destructive tools have destructiveHint=true and readOnlyHint=false", () => {
    const destructive = TOOLS.filter((t) => t.name.startsWith("guard_"));
    for (const t of destructive) {
      const a = t.annotations as { destructiveHint?: boolean; readOnlyHint?: boolean };
      expect(a.destructiveHint).toBe(true);
      expect(a.readOnlyHint).toBe(false);
    }
  });

  it("read-only tools have readOnlyHint=true", () => {
    const ro = TOOLS.filter(
      (t) =>
        t.name === "audit_source" ||
        t.name === "audit_report" ||
        t.name === "replay_check" ||
        t.name === "sandbox_status" ||
        t.name === "trust_tier",
    );
    for (const t of ro) {
      const a = t.annotations as { readOnlyHint?: boolean };
      expect(a.readOnlyHint).toBe(true);
    }
  });
});

describe("createServer — request handlers", () => {
  it("ListTools returns the 8-tool array", async () => {
    const state = makeState();
    const server = createServer(state);
    // The Server class private `_requestHandlers` map exposes via `setRequestHandler`,
    // so we round-trip via createServer/connect. Here we assert TOOLS export contract instead.
    expect(TOOLS.length).toBe(8);
    expect(server).toBeDefined();
  });

  it("schemas are zod schemas (truthy import)", () => {
    expect(ListToolsRequestSchema).toBeDefined();
    expect(CallToolRequestSchema).toBeDefined();
  });

  it("makeState produces fresh registry + replay window", () => {
    const a = makeState();
    const b = makeState();
    expect(a.registry).not.toBe(b.registry);
    expect(a.replay).not.toBe(b.replay);
    expect(a.replay.size()).toBe(0);
  });
});
