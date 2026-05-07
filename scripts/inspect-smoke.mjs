#!/usr/bin/env node
// Smoke-test the reference MCP server by spawning it as a stdio child,
// sending a `tools/list` request, and asserting we get 8 tools back.
// Used by `npm run inspect:smoke` and CI.

import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const SERVER_BIN = path.resolve(here, "..", "dist", "server.js");
const TIMEOUT_MS = 5000;

function send(child, msg) {
  child.stdin.write(JSON.stringify(msg) + "\n");
}

async function main() {
  const child = spawn("node", [SERVER_BIN], {
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, NODE_ENV: "test" },
  });

  let buf = "";
  let resolved = false;
  let toolCount = 0;
  let error = null;

  child.stdout.on("data", (chunk) => {
    buf += chunk.toString("utf8");
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      if (!line.trim()) continue;
      try {
        const msg = JSON.parse(line);
        if (msg.id === 2 && msg.result?.tools) {
          toolCount = msg.result.tools.length;
          resolved = true;
        }
      } catch {
        // ignore parse errors; server may emit non-JSON
      }
    }
  });

  child.stderr.on("data", (chunk) => {
    process.stderr.write(`[server stderr] ${chunk}`);
  });

  child.on("error", (err) => {
    error = err;
  });

  // initialize handshake
  send(child, {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "inspect-smoke", version: "0.0.0" },
    },
  });

  await delay(200);

  send(child, {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/list",
    params: {},
  });

  const start = Date.now();
  while (!resolved && Date.now() - start < TIMEOUT_MS && !error) {
    await delay(50);
  }

  child.kill("SIGTERM");
  await delay(200);
  if (!child.killed) child.kill("SIGKILL");

  if (error) {
    console.error("smoke: server spawn error:", error.message);
    process.exit(2);
  }
  if (!resolved) {
    console.error("smoke: timed out waiting for tools/list response");
    process.exit(2);
  }
  if (toolCount !== 8) {
    console.error(`smoke: expected 8 tools, got ${toolCount}`);
    process.exit(1);
  }
  console.log(`smoke: OK (${toolCount} tools)`);
  process.exit(0);
}

main().catch((err) => {
  console.error("smoke: unexpected:", err);
  process.exit(2);
});
