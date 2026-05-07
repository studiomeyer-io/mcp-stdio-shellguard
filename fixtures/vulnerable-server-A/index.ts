/**
 * Fixture A — vulnerable MCP server reference. NEVER EXECUTED.
 *
 * The audit scanner walks this file as static text and the patterns
 * fire deterministically. Plan success-criterion: >=3 CRITICAL + >=2 HIGH
 * findings.
 *
 * shellguard:ignore-file would suppress findings — we INTENTIONALLY do
 * not set it here, this fixture must produce findings.
 */

import { exec, execSync, execFile, spawn } from "node:child_process";

declare const userInput: string;
declare const dynamicCmd: string;
declare const dynamicArgs: string[];
declare function arbitrary(): unknown;

// CRITICAL #1 — template literal with interpolation in exec()
exec(`git log ${userInput}`, () => {
  /* noop */
});

// CRITICAL #2 — exec() with dynamic string (concatenation)
exec("echo " + userInput, () => {
  /* noop */
});

// CRITICAL #3 — execSync with dynamic string
const out = execSync(dynamicCmd);
void out;

// CRITICAL #4 — eval next to child_process
eval("require('child_process').exec('id', () => {})");

// CRITICAL #5 — Function constructor next to child_process
const fn = Function("return require('child_process').execSync('whoami')");
void fn;

// HIGH #1 — execFile with dynamic file
execFile(dynamicCmd, ["-l"], () => {
  /* noop */
});

// HIGH #2 — spawn with dynamic file + dynamic args
spawn(dynamicCmd, dynamicArgs);

// HIGH #3 — shell:true option
spawn("ls", ["-la"], { shell: true });

void arbitrary;
