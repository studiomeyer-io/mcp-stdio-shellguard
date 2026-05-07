/**
 * Fixture B — mixed LOW/MEDIUM/HIGH MCP server. NEVER EXECUTED.
 *
 * Tests the severity floor + sort + de-dup. No CRITICAL findings here.
 */

import { spawn, exec, execFile } from "node:child_process";

declare const userArgs: string[];

// MEDIUM — literal exe + dynamic args
spawn("git", userArgs);

// HIGH — execFile with dynamic file
declare const dynFile: string;
execFile(dynFile, ["--help"]);

// LOW — exec without maxBuffer / timeout
exec("ls -la", () => {
  /* noop */
});

// LOW — exec with maxBuffer but no timeout
exec("ls -la", { maxBuffer: 1024 * 1024 }, () => {
  /* noop */
});

// MEDIUM — spawn(literal, dynamic-args) again (dedup test)
spawn("rg", userArgs);
