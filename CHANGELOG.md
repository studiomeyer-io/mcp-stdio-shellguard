# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
