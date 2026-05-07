/**
 * Fixture safe — what a hardened MCP stdio server looks like. The audit
 * scanner must produce ZERO findings against this file (modulo
 * configurable LOW patterns; default floor LOW yields exactly 0 too).
 */

import { spawn } from "node:child_process";

// All-literal: literal file, literal args array, options object includes
// timeout so unbounded_buffer + missing_timeout don't fire.
spawn("git", ["--version"], { timeout: 5_000 });

// Another safe call: same shape
spawn("node", ["--version"], { timeout: 5_000 });

// shellguard:ignore-next-line
// (above pragma demonstrates the suppression hook; not needed here.)
