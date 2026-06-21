# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2026-06-21

### Security — audit alias-bypass class closed

A cold-cross follow-up review of v0.1.1 found that the AST audit
(`mcp-shellguard-audit`) attributed a `child_process` call to its method
only by the *callee name* (`child_process.exec`, bare `exec`, …). Four
false-negative shapes — all common in real MCP servers — therefore
passed the scan with zero findings, giving false confidence that a
server was clean:

- **`const execAsync = promisify(exec); execAsync(`ls ${x}`)`** — the
  canonical way servers `await` exec. Now resolved to `exec` and flagged.
- **`import cp from "node:child_process"; cp.exec(`ls ${x}`)`** via a
  default/namespace import bound to an arbitrary local name.
- **`const { exec: sh } = require("child_process"); sh(`ls ${x}`)`** —
  destructure-rename off `require`.
- **`import { exec as run } from "node:child_process"; run(...)`** —
  named-import alias.

New `src/audit/bindings.ts` runs a whole-program pre-pass that resolves
every local identifier / namespace member proven to originate from
`child_process` (import or `require("child_process")`) to its canonical
method, then the scanner attributes the call accordingly. The resolver
is purely **additive** on top of the existing name-based matching, so it
can never *lose* a finding, and it only maps bindings whose origin is
proven — a `promisify(readFile)` or a destructure off another module
stays clean.

- **String-shell + dynamic-shell bypass.** `objectHasShellTrue` matched
  only the literal `shell: true`. `{ shell: "/bin/bash" }` (Node runs a
  real shell for a string shell) slipped through as a mere MEDIUM, and a
  dynamic `{ shell: shVar }` was not flagged at all. Both are now HIGH
  `shell_true_option`. `shell: false` / `shell: ""` stay clean.
- **Sync child_process variants.** `spawnSync` and `execFileSync` were
  uncovered. `spawnSync("sh", ["-c", x], { shell: true })` and
  `execFileSync(<dynamic>)` are now flagged alongside their async forms
  in `spawn_dynamic_file_args`, `exec_file_dynamic`, `shell_true_option`,
  `spawn_literal_dynamic_args`, `unbounded_buffer` and `missing_timeout`.

### Security — guard arg-type hardening (defense-in-depth)

`guardExec` / `guardSpawn` now reject any non-string element in `args`.
The TS type is `string[]`, but the library is reachable from untyped JS
and JSON tool paths where an arg can arrive as a number / object / null.
Both the allowlist regex (`re.test`) and `spawn` silently coerce such
values, so a non-string arg could slip past an `argsPattern` the
operator believed constrained the input (most exposed at the MEDIUM tier
where `argsPatterns` is empty). `guardSpawn` also gained the explicit
`Array.isArray(args)` check `guardExec` already had.

### Tests

- `tests/audit-binding-bypass.test.ts` (16) — attack-blocked + benign-
  allowed for every alias / sync / string-shell shape, plus binding-
  resolver unit tests.
- `tests/guard-arg-types.test.ts` (8) — non-string-arg rejection for both
  guards, with benign string-arg passthrough.
- `tests/audit-patterns.test.ts` extended (+2) for string/dynamic-shell
  and `isChildProcessMethod`.
- Total test count: 149 -> 167. No existing test weakened; the 12-rule
  catalogue is unchanged (rules broadened, no IDs added or removed).

## [0.1.1] - 2026-05-29

### Added

- Listed on the Official MCP Registry as `io.studiomeyer/stdio-shellguard`
  (`mcpName` + `server.json` + package-name `bin` alias).
- Live shields.io badges block + StudioMeyer MCP Stack banner in README.

## [0.1.0] - 2026-05-07

### Added

- `guard_exec` / `guard_spawn` library wrappers around `child_process.exec`/`spawn`
  with default-deny behaviour and per-tool allowlist registry.
- Process sandbox: wall-clock timeout, stdout/stderr byte caps, FD budget,
  optional cgroup-v2 limits when running as root with writable
  `/sys/fs/cgroup`.
- Replay detection via SHA-256 over canonicalised `(executable, args, cwd, envSubset)`
  with in-memory LRU sliding window (default 1000 entries, 60 min TTL).
- Audit CLI `mcp-shellguard-audit scan <path>` covering 12 AST patterns
  (CRITICAL/HIGH/MEDIUM/LOW) using `@typescript-eslint/parser` plus
  `fast-glob`.
- Audit reports in markdown, JSON and SARIF 2.1.0 formats.
- Trust tier derivation (LOW/MEDIUM/HIGH/CRITICAL) per registered tool, with
  improvement hints.
- Reference MCP stdio server exposing 8 tools that wrap library + audit.
- Three test fixtures (`vulnerable-server-A`, `vulnerable-server-B`,
  `safe-server`) for deterministic audit gegen-Tests.
- 149 vitest unit + integration tests across 14 files.
- MIT licence, GitHub provenance + Sigstore attest CI workflow.

### Security

- Closes the unsanitized `child_process.exec` / `spawn` shell-injection class
  reported in the Ox-Security MCP audit (200k servers exposed) and the
  LiteLLM CVE patched in v1.83.7.

### Round 2 Cold-Cross-Review hardening (pre-promotion, 2026-05-07)

Two cold-cross reviewers (Critic + Architect) reviewed the build before
the first public release and flagged three HIGH bypass classes. All three
are closed in this v0.1.0 cut; the changes are listed here so anyone
auditing the repository can find them in one place.

- **Allowlist-Regex Unicode bypass.** `AllowlistRegistry.match` now
  applies NFKC compatibility-normalisation and strips zero-width /
  bidi-formatting / invisible-math-operator codepoints before testing
  args against the registered regexes. An attacker who substituted
  fullwidth letters or appended a zero-width joiner could previously
  smuggle past `^log$`. The wire-form arg is preserved in the failure
  reason so the audit trail still shows the original input.
- **Replay-Window Unicode bypass.** `canonicalize` now normalises the
  executable, every arg, the cwd, and every env value before hashing.
  An attacker who knew the replay TTL could previously generate a
  different SHA-256 on each call by appending a random ZWC and silently
  defeat replay detection. Two requests that differ only by zero-width
  characters now hash to the same canonical and the second is reported
  as `isReplay: true`.
- **exec/spawn whitespace check.** `guardExec` and `guardSpawn` now
  reject `command` / `file` strings that contain any Unicode whitespace
  (U+00A0 NBSP, U+1680 OGHAM, U+2000-U+200A, U+202F, U+205F, U+3000
  IDEOGRAPHIC, U+FEFF) instead of only ASCII space. The previous
  `includes(" ")` check gave false confidence on inputs like
  `"/usr/bin/sh -c"`.
- **Audit pattern `shell_true_option` was position-blind.** The pattern
  inspected only `args[args.length - 1]` so `spawn(file, args, { shell: true }, callback)`
  was missed whenever a callback was the final argument. The rule now
  scans every `ObjectExpression` argument.
- **HOOK_RECIPES.md Recipe 2 + 4** corrected: `npx -y <package> <bin>`
  does not invoke the bin when the bin name differs from the package
  name. Replaced with the correct `npx -y -p <package> <bin>` form.
- **HOOK_RECIPES.md Recipe 3** removed the hard-coded `tier=LOW`
  string from the journal line. The raw `Bash` tool does not route
  through `guardExec` / `guardSpawn`, so the tier is unknown by
  definition; emitting `tier=LOW` was misleading.
- **CI publish workflow** now generates a Sigstore build-provenance
  attestation via `actions/attest-build-provenance@v2` against the
  packed tarball before `npm publish --provenance`. Brings the build
  in line with the other published Foundation-Pillars (mcp-armor,
  studiomeyer-aishield) which already ship attested provenance.

Six of the eleven cold-cross findings were promoted to fixes in v0.1.0
above. The remaining five (replay-window TTL monotonicity, in-tree
zod-to-JSON-Schema bridge, fdBudget enforcement via `setrlimit`, README
trust-tier-pattern attribution to mcp-server-attestation, MEDIUM-rank
inspector entry-point default) are tracked in BUILDER_NOTES.md as
v0.1.1 / v0.2 backlog. None of those five is exploitable in v0.1.0.

40 regression tests in `tests/normalize.test.ts` (22) and
`tests/round-2-cold-cross.test.ts` (18) bind these fixes to behaviour.
Total test count: 109 → 149 (+36.7%).
