# Claude Code Hook Recipes

Drop-in hook configurations that wire `mcp-stdio-shellguard` into your Claude
Code session. Hooks live in `~/.claude/settings.json` (user-global) or in a
project's `.claude/settings.json` (per-project).

All recipes are defensive: they BLOCK or LOG, never extend execution.

## 1. PreToolUse — Block dangerous Bash patterns

Stops the tool call before any shell runs if the model tries to issue an
`exec`-shaped command with template-literal interpolation or `shell:true`.

```json
{
  "hooks": [
    {
      "match": { "tool": "Bash" },
      "type": "PreToolUse",
      "command": "node -e \"const {scanText}=require('mcp-stdio-shellguard/dist/audit/scanner.js');const r=scanText(process.env.CLAUDE_TOOL_INPUT_command||'',{severityFloor:'HIGH'});if(r.findings.length){console.error('blocked:',r.findings[0].rule);process.exit(2);}\""
    }
  ]
}
```

Exit code `2` aborts the tool call. The model receives the stderr line
`blocked: <rule-id>` and re-plans.

## 2. PreToolUse — Audit on Edit/Write

Whenever Claude writes a TS/JS file, scan the new contents for shell-injection
anti-patterns BEFORE the write commits.

```json
{
  "hooks": [
    {
      "match": { "tool": ["Edit", "Write"], "filePathPattern": "\\.(ts|tsx|js|mjs|cjs)$" },
      "type": "PreToolUse",
      "command": "npx -y -p mcp-stdio-shellguard mcp-shellguard-audit scan ${CLAUDE_TOOL_INPUT_file_path} --severity-floor HIGH --format json"
    }
  ]
}
```

The `--severity-floor HIGH` gate means LOW/MEDIUM warnings are surfaced as
informational output; HIGH+CRITICAL block the edit (CLI exit code 1).

## 3. PostToolUse — Audit-trail journal

After every `Bash` tool call, append the command to the session journal so a
retrospective auditor can answer "which tools ran with which inputs?". The
recipe deliberately does NOT emit a tier — the raw `Bash` tool does not route
through `guardExec` / `guardSpawn`, so the tier is unknown by definition. To
get an actual tier, use the reference MCP server's `trust_tier` tool from
inside Claude (it reads the registry state of the running shellguard server).

```json
{
  "hooks": [
    {
      "match": { "tool": "Bash" },
      "type": "PostToolUse",
      "command": "printf '[shellguard] %s tool=Bash command=%s\\n' \"$(date -Iseconds)\" \"${CLAUDE_TOOL_INPUT_command}\" >> ~/.claude/shellguard-journal.log"
    }
  ]
}
```

## 4. SessionStart — Guard init banner

Loads the audit summary of the project source on every session start. Catches
regressions early (the AI sees the warnings in its initial context).

```json
{
  "hooks": [
    {
      "type": "SessionStart",
      "command": "npx -y -p mcp-stdio-shellguard mcp-shellguard-audit scan ./src --severity-floor MEDIUM --format markdown"
    }
  ]
}
```

The markdown summary is injected into the model's first-turn context.

## Caveats

- Recipes 2 + 4 use `npx -y -p mcp-stdio-shellguard mcp-shellguard-audit ...`.
  The `-p <package>` form is the correct way to invoke a `bin` whose name
  differs from the package name. In offline / hermetic environments install
  the package locally and call `node ./node_modules/.bin/mcp-shellguard-audit`
  instead.
- Hook commands run with Claude Code's environment. If your CI uses a
  read-only home, point the journal log to a writable path.
- Exit codes are honored by Claude Code: `0` = allow, `1` = warn, `2` = block.
- The hooks complement, but do NOT replace, the in-server `guardExec` /
  `guardSpawn` calls. Belt and suspenders: hook gates the request, guard
  gates the syscall.
