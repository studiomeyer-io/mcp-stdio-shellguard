import { describe, it, expect } from "vitest";
import { ReplayWindow } from "../src/guard/replay.js";

describe("ReplayWindow", () => {
  it("first record returns isReplay=false", () => {
    const w = new ReplayWindow();
    const r = w.record("aa");
    expect(r.isReplay).toBe(false);
    expect(r.canonicalHash).toBe("aa");
    expect(r.windowSize).toBe(1);
  });

  it("second record of same hash returns isReplay=true", () => {
    const w = new ReplayWindow();
    w.record("aa");
    const r2 = w.record("aa");
    expect(r2.isReplay).toBe(true);
    expect(r2.lastSeenAtMs).toBeTypeOf("number");
  });

  it("peek does not mutate window order", () => {
    const w = new ReplayWindow();
    w.record("aa");
    const p = w.peek("bb");
    expect(p.isReplay).toBe(false);
    expect(w.size()).toBe(1);
  });

  it("evicts entries past TTL", () => {
    let now = 0;
    const w = new ReplayWindow({ ttlMs: 100, now: () => now });
    w.record("aa");
    now = 1000;
    expect(w.size()).toBe(0);
  });

  it("respects capacity (LRU eviction)", () => {
    const w = new ReplayWindow({ capacity: 2 });
    w.record("a");
    w.record("b");
    w.record("c");
    expect(w.size()).toBe(2);
    expect(w.peek("a").isReplay).toBe(false);
    expect(w.peek("b").isReplay).toBe(true);
    expect(w.peek("c").isReplay).toBe(true);
  });

  it("clear empties the window", () => {
    const w = new ReplayWindow();
    w.record("a");
    w.record("b");
    w.clear();
    expect(w.size()).toBe(0);
  });

  it("re-recording refreshes recency (LRU)", () => {
    const w = new ReplayWindow({ capacity: 2 });
    w.record("a");
    w.record("b");
    // touch 'a' so 'b' becomes oldest
    w.record("a");
    w.record("c");
    expect(w.peek("a").isReplay).toBe(true);
    expect(w.peek("b").isReplay).toBe(false);
    expect(w.peek("c").isReplay).toBe(true);
  });

  it("peek reports lastSeenAtMs after record", () => {
    let now = 1000;
    const w = new ReplayWindow({ now: () => now });
    w.record("aa");
    now = 2000;
    const p = w.peek("aa");
    expect(p.isReplay).toBe(true);
    expect(p.lastSeenAtMs).toBe(1000);
  });
});
