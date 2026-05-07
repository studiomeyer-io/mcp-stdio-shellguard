/**
 * In-memory LRU sliding window of canonical hashes. Used to detect
 * replays of the same command within a TTL window. Pure local-process,
 * no disk persistence in v0.1.0.
 */

export interface ReplayEntry {
  hash: string;
  lastSeenAtMs: number;
}

export interface ReplayCheckResult {
  canonicalHash: string;
  isReplay: boolean;
  lastSeenAtMs?: number;
  windowSize: number;
}

export interface ReplayWindowOptions {
  capacity?: number;
  ttlMs?: number;
  /**
   * Clock injection for deterministic tests. Defaults to Date.now.
   */
  now?: () => number;
}

const DEFAULT_CAPACITY = 1000;
const DEFAULT_TTL_MS = 60 * 60 * 1000;

export class ReplayWindow {
  private readonly capacity: number;
  private readonly ttlMs: number;
  private readonly now: () => number;
  /** Map preserves insertion order — used as LRU. */
  private readonly entries: Map<string, ReplayEntry>;

  constructor(opts: ReplayWindowOptions = {}) {
    this.capacity = opts.capacity ?? DEFAULT_CAPACITY;
    this.ttlMs = opts.ttlMs ?? DEFAULT_TTL_MS;
    this.now = opts.now ?? Date.now;
    this.entries = new Map();
  }

  size(): number {
    this.evictExpired();
    return this.entries.size;
  }

  /**
   * Record a hash. Returns true if this hash was already present
   * (within TTL) — i.e. this call is a replay.
   */
  record(hash: string): ReplayCheckResult {
    this.evictExpired();
    const now = this.now();
    const existing = this.entries.get(hash);
    let isReplay = false;
    let lastSeenAtMs: number | undefined;
    if (existing) {
      isReplay = true;
      lastSeenAtMs = existing.lastSeenAtMs;
      // refresh recency
      this.entries.delete(hash);
    }
    this.entries.set(hash, { hash, lastSeenAtMs: now });
    this.evictOverCapacity();
    const result: ReplayCheckResult = {
      canonicalHash: hash,
      isReplay,
      windowSize: this.entries.size,
    };
    if (lastSeenAtMs !== undefined) {
      result.lastSeenAtMs = lastSeenAtMs;
    }
    return result;
  }

  /**
   * Read-only check (does not refresh recency or insert).
   */
  peek(hash: string): ReplayCheckResult {
    this.evictExpired();
    const existing = this.entries.get(hash);
    const result: ReplayCheckResult = {
      canonicalHash: hash,
      isReplay: existing !== undefined,
      windowSize: this.entries.size,
    };
    if (existing) {
      result.lastSeenAtMs = existing.lastSeenAtMs;
    }
    return result;
  }

  clear(): void {
    this.entries.clear();
  }

  private evictExpired(): void {
    const cutoff = this.now() - this.ttlMs;
    for (const [hash, entry] of this.entries) {
      if (entry.lastSeenAtMs < cutoff) {
        this.entries.delete(hash);
      } else {
        // Map iterates in insertion order; first non-expired entry
        // means everything after is also non-expired (since we
        // re-insert on touch so age is monotonic).
        break;
      }
    }
  }

  private evictOverCapacity(): void {
    while (this.entries.size > this.capacity) {
      const oldest = this.entries.keys().next();
      if (oldest.done || oldest.value === undefined) {
        return;
      }
      this.entries.delete(oldest.value);
    }
  }
}
