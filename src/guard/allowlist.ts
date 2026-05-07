/**
 * Per-tool allowlist registry. Each tool whitelists exactly one
 * executable path plus an args-pattern array (regex strings). Optional
 * cwd glob via picomatch. Default-deny: a tool that has not been
 * registered cannot execute anything.
 */

import picomatch from "picomatch";
import { ShellguardError } from "./errors.js";
import { normalizeForMatching } from "./normalize.js";

export type SandboxProfile = "strict" | "standard" | "permissive";

export interface AllowlistEntryInput {
  toolName: string;
  executable: string;
  argsPatterns: string[];
  cwdPattern?: string;
  sandboxProfile?: SandboxProfile;
}

export interface AllowlistEntry {
  toolName: string;
  executable: string;
  argsRegex: readonly RegExp[];
  cwdMatch?: (cwd: string) => boolean;
  cwdPattern?: string;
  sandboxProfile: SandboxProfile;
}

export interface AllowlistMatchInput {
  toolName: string;
  executable: string;
  args: readonly string[];
  cwd?: string;
}

export interface AllowlistMatchResult {
  allowed: boolean;
  reason?: string;
  entry?: AllowlistEntry;
}

export class AllowlistRegistry {
  private readonly entries: Map<string, AllowlistEntry> = new Map();

  register(input: AllowlistEntryInput): AllowlistEntry {
    if (!input.toolName || !input.executable) {
      throw new ShellguardError(
        "SHELLGUARD_INVALID_REGISTRATION",
        "toolName and executable are required",
      );
    }
    const argsRegex: RegExp[] = [];
    for (const pattern of input.argsPatterns) {
      try {
        argsRegex.push(new RegExp(pattern));
      } catch (err) {
        throw new ShellguardError(
          "SHELLGUARD_INVALID_REGISTRATION",
          `invalid argsPattern '${pattern}': ${(err as Error).message}`,
          { toolName: input.toolName, pattern },
        );
      }
    }

    const entry: AllowlistEntry = {
      toolName: input.toolName,
      executable: input.executable,
      argsRegex,
      sandboxProfile: input.sandboxProfile ?? "standard",
    };
    if (input.cwdPattern !== undefined) {
      entry.cwdPattern = input.cwdPattern;
      entry.cwdMatch = picomatch(input.cwdPattern, { dot: true });
    }
    this.entries.set(input.toolName, entry);
    return entry;
  }

  unregister(toolName: string): boolean {
    return this.entries.delete(toolName);
  }

  get(toolName: string): AllowlistEntry | undefined {
    return this.entries.get(toolName);
  }

  list(): AllowlistEntry[] {
    return [...this.entries.values()];
  }

  has(toolName: string): boolean {
    return this.entries.has(toolName);
  }

  clear(): void {
    this.entries.clear();
  }

  match(input: AllowlistMatchInput): AllowlistMatchResult {
    const entry = this.entries.get(input.toolName);
    if (!entry) {
      return {
        allowed: false,
        reason: `tool '${input.toolName}' not registered (default-deny)`,
      };
    }
    if (entry.executable !== input.executable) {
      return {
        allowed: false,
        reason:
          `executable mismatch: registered='${entry.executable}', ` +
          `requested='${input.executable}'`,
        entry,
      };
    }
    if (entry.argsRegex.length > 0) {
      // every requested arg must match at least one allowed regex.
      // We normalise the arg first so an attacker cannot bypass `^log$`
      // by appending a zero-width joiner or substituting fullwidth
      // letters. The original (un-normalised) arg is reported in the
      // failure reason so the audit trail still shows what was sent.
      for (const arg of input.args) {
        const normalised = normalizeForMatching(arg);
        const ok = entry.argsRegex.some((re) => re.test(normalised));
        if (!ok) {
          return {
            allowed: false,
            reason: `arg '${arg}' does not match any argsPattern`,
            entry,
          };
        }
      }
    }
    if (entry.cwdMatch && input.cwd !== undefined) {
      if (!entry.cwdMatch(input.cwd)) {
        return {
          allowed: false,
          reason: `cwd '${input.cwd}' does not match cwdPattern '${entry.cwdPattern}'`,
          entry,
        };
      }
    }
    return { allowed: true, entry };
  }
}
