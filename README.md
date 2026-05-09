# mcp-stdio-shellguard


<!-- badges -->
[![npm version](https://img.shields.io/npm/v/mcp-stdio-shellguard?style=flat-square&color=cb3837&logo=npm&label=npm)](https://www.npmjs.com/package/mcp-stdio-shellguard)
[![npm downloads](https://img.shields.io/npm/dm/mcp-stdio-shellguard?style=flat-square&color=cb3837&logo=npm&label=installs%2Fmo)](https://www.npmjs.com/package/mcp-stdio-shellguard)
![License](https://img.shields.io/github/license/studiomeyer-io/mcp-stdio-shellguard?style=flat-square&color=22c55e&label=license)
![Last commit](https://img.shields.io/github/last-commit/studiomeyer-io/mcp-stdio-shellguard?style=flat-square&color=88c0d0&label=updated)
![GitHub stars](https://img.shields.io/github/stars/studiomeyer-io/mcp-stdio-shellguard?style=flat-square&color=ffd700&logo=github&label=stars)
<!-- /badges -->Defense-in-depth bundle for MCP stdio servers. Wraps `child_process.exec/spawn`
with allowlist + sandbox + replay-detection, plus an AST audit CLI (`mcp-shellguard-audit`)
that scans MCP server sources for unsanitized shell calls. Closes the Ox-Security
MCP stdio-RCE class (200k vulnerable servers, May 2026 disclosure).

- **MCP spec**: 2025-06-18
- **SDK**: `@modelcontextprotocol/sdk` ^1.29.0
- **Node**: >= 20
- **License**: MIT
- **Author**: Matthias Meyer (StudioMeyer)

## Install

```bash
npm install mcp-stdio-shellguard
```

Or run the audit CLI directly without installing:

```bash
npx -y -p mcp-stdio-shellguard mcp-shellguard-audit scan ./src
```

## What it gives you

Three layers, opt-in piecewise:

1. **Library API** — drop-in `guardExec` / `guardSpawn` you call from your
   own MCP server. Default-deny allowlist, sandbox profiles, replay window.
2. **Audit CLI** — `mcp-shellguard-audit scan <path>` walks the AST, reports
   12 anti-patterns from LOW (`no timeout`) to CRITICAL (`exec(\`...${userInput}...\`)`).
3. **Reference MCP server** — `mcp-stdio-shellguard-demo` exposes 8 tools
   so the MCP Inspector / Claude Desktop can drive the bundle directly.

## Tools (reference server)

| Tool | Type | Purpose |
|------|------|---------|
| `guard_exec` | destructive | Defended `child_process.exec`. Forces args[] vector, allowlist + sandbox + replay. Returns `stdout`, `stderr`, `exitCode`, `canonicalHash`, `isReplay`, `trustTier`. |
| `guard_spawn` | destructive | Defended `child_process.spawn`. Returns SHA-256 hashes of stdout/stderr instead of full bodies. Hard-rejects `shell:true`. |
| `register_allowlist` | mutating | Register a tool name with executable + args regex. Without registration the default-deny applies. |
| `audit_source` | read-only | Scan a TS/JS path for shell-injection anti-patterns. Returns `AuditFinding[]` + summary. |
| `audit_report` | read-only | Format an audit result as markdown / json / SARIF 2.1.0. |
| `replay_check` | read-only | Compute canonical SHA-256 hash for an invocation and report whether it's already in the replay window. |
| `sandbox_status` | read-only | Report active sandbox profile + concrete limits + cgroup-v2 active flag. |
| `trust_tier` | read-only | Derive LOW/MEDIUM/HIGH/CRITICAL tier for a registered tool plus improvement hints. |

## Sandbox profiles

| Profile | Timeout | Max stdout | Max stderr | FD budget | cgroup-v2 |
|---------|---------|-----------|-----------|-----------|-----------|
| `strict` | 5 s | 1 MB | 256 KB | 32 | yes (cpu/memory) |
| `standard` (default) | 30 s | 10 MB | 1 MB | 256 | yes |
| `permissive` | 5 min | 100 MB | 10 MB | 1024 | no |

Caller can tighten via `timeoutMs` / `fdBudget` per call. Caller cannot widen
beyond the profile.

## Trust tiers

| Tier | Condition |
|------|-----------|
| LOW | tool not registered (default-deny) |
| MEDIUM | registered but `argsPatterns` empty (any args allowed) |
| HIGH | `argsPatterns` set but sandbox or replay tracker inactive |
| CRITICAL | argsPatterns + sandbox + replay all active |

Lift LOW → CRITICAL by registering the tool + setting argsPatterns + running
through `guardExec`/`guardSpawn` (which always activate sandbox + replay).

## Library quickstart

```ts
import {
  AllowlistRegistry,
  ReplayWindow,
  guardExec,
} from "mcp-stdio-shellguard";

const registry = new AllowlistRegistry();
const replay = new ReplayWindow();

registry.register({
  toolName: "git-log",
  executable: "/usr/bin/git",
  argsPatterns: ["^log$", "^--oneline$", "^-n$", "^\\d+$"],
  sandboxProfile: "strict",
});

const result = await guardExec(
  {
    toolName: "git-log",
    command: "/usr/bin/git",
    args: ["log", "--oneline", "-n", "10"],
  },
  { registry, replay },
);

console.log(result.stdout); // → commit lines
console.log(result.trustTier); // → "CRITICAL"
console.log(result.canonicalHash); // → 64-char SHA-256
```

## Audit CLI

```bash
mcp-shellguard-audit scan ./src
mcp-shellguard-audit scan ./src --format sarif --output audit.sarif
mcp-shellguard-audit scan ./src --severity-floor HIGH    # CI gate
```

Exit codes:

- `0` clean (no findings at-or-above floor)
- `1` findings present
- `2` parse / IO errors

## Anti-pattern library (12 rules)

| ID | Severity | Triggers on |
|----|----------|-------------|
| `exec_template_literal_with_input` | CRITICAL | `child_process.exec(\`ls ${x}\`)` |
| `exec_dynamic_string` | CRITICAL | `child_process.exec(cmd)` |
| `exec_sync_dynamic_string` | CRITICAL | `child_process.execSync(cmd)` |
| `eval_near_child_process` | CRITICAL | `eval(...)` |
| `function_constructor_near_child_process` | CRITICAL | `new Function(...)` |
| `spawn_dynamic_file_args` | HIGH | `spawn(bin, userArgs)` |
| `exec_file_dynamic` | HIGH | `execFile(bin, ...)` |
| `shell_true_option` | HIGH | `{ shell: true }` |
| `os_system_equivalent` | HIGH | `Deno.run` / `Bun.spawn` |
| `spawn_literal_dynamic_args` | MEDIUM | `spawn('git', userArgs)` |
| `unbounded_buffer` | LOW | exec without `maxBuffer` |
| `missing_timeout` | LOW | exec/spawn without `timeout` |

## Pragmas

- `// shellguard:ignore-next-line` — suppress one finding
- `// shellguard:ignore-file` — suppress whole file (rare; prefer per-line)

## Why this exists

Ox-Security disclosed (2026-05) that 200k+ MCP stdio servers wrap
`child_process.exec` with template literals carrying user input straight from
LLM tool args. LiteLLM v1.83.6 was the canonical example (CVE patched in 1.83.7).
This bundle is the defensive-security counterpart: a drop-in guard + scanner
that closes the class. Inspired by AWS Linux `seccomp` + Chromium sandbox tiers.

## See also

- `HOOK_RECIPES.md` — Claude Code hook recipes that auto-block dangerous tool calls
- `CHANGELOG.md` — release history
- Ox-Security MCP audit: <https://venturebeat.com/security/200000-mcp-stdio-servers/>
- LiteLLM CVE-2026-XXXX: <https://github.com/BerriAI/litellm/security/advisories>

## License

MIT — Copyright (c) 2026 Matthias Meyer (StudioMeyer)
