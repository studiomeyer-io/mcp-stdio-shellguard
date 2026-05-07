#!/usr/bin/env node
/**
 * Reference MCP stdio server for `mcp-stdio-shellguard`.
 *
 * Exposes 8 tools that wrap the library + audit CLI so the demo can
 * be driven by the official MCP Inspector (and Claude Desktop /
 * Continue / etc.). Trust-tier output piggybacks on the library's
 * deriveTrustTier().
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { AllowlistRegistry } from "./guard/allowlist.js";
import { ReplayWindow } from "./guard/replay.js";
import { canonicalHash } from "./guard/canonical.js";
import { guardExec } from "./guard/exec.js";
import { guardSpawn } from "./guard/spawn.js";
import { deriveTrustTier } from "./guard/tier.js";
import { resolveLimits, probeCgroupV2 } from "./guard/sandbox.js";
import type { SandboxStatus } from "./guard/sandbox.js";
import { scanPath } from "./audit/scanner.js";
import { renderReport, type ReportFormat } from "./audit/report.js";
import {
  ShellguardDenied,
  ShellguardError,
  ShellguardLimitExceeded,
  ShellguardTimeout,
} from "./guard/errors.js";

// ---------------------------------------------------------------------------
// Version (read from package.json — never hardcode, drift-prone)
// ---------------------------------------------------------------------------

function readVersion(): string {
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const candidates = [
      path.resolve(here, "../package.json"),
      path.resolve(here, "../../package.json"),
    ];
    for (const c of candidates) {
      try {
        const pkg = JSON.parse(readFileSync(c, "utf8")) as { version?: string };
        if (pkg.version) return pkg.version;
      } catch {
        // try next
      }
    }
  } catch {
    // fall through
  }
  return "0.0.0-dev";
}

const VERSION = readVersion();

// ---------------------------------------------------------------------------
// Tool input schemas (zod)
// ---------------------------------------------------------------------------

const RecordEnv = z.record(z.string());

const GuardExecArgs = z.object({
  toolName: z.string().min(1),
  command: z.string().min(1),
  args: z.array(z.string()),
  cwd: z.string().optional(),
  env: RecordEnv.optional(),
  timeoutMs: z.number().int().positive().optional(),
  blockOnReplay: z.boolean().optional(),
});

const GuardSpawnArgs = z.object({
  toolName: z.string().min(1),
  file: z.string().min(1),
  args: z.array(z.string()),
  cwd: z.string().optional(),
  env: RecordEnv.optional(),
  fdBudget: z.number().int().positive().optional(),
  shell: z.boolean().optional(),
});

const RegisterAllowlistArgs = z.object({
  toolName: z.string().min(1),
  executable: z.string().min(1),
  argsPatterns: z.array(z.string()),
  cwdPattern: z.string().optional(),
  sandboxProfile: z.enum(["strict", "standard", "permissive"]).optional(),
});

const AuditSourceArgs = z.object({
  path: z.string().min(1),
  ignoreGlobs: z.array(z.string()).optional(),
  severityFloor: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).optional(),
});

const AuditReportArgs = z.object({
  findings: z.unknown(),
  format: z.enum(["markdown", "json", "sarif"]),
});

const ReplayCheckArgs = z.object({
  executable: z.string().min(1),
  args: z.array(z.string()),
  cwd: z.string().optional(),
  env: RecordEnv.optional(),
  record: z.boolean().optional(),
});

const SandboxStatusArgs = z.object({
  toolName: z.string().optional(),
});

const TrustTierArgs = z.object({
  toolName: z.string().min(1),
});

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------

export const TOOLS: Tool[] = [
  {
    name: "guard_exec",
    description:
      "Defended replacement for child_process.exec. Forces an args[] vector, " +
      "runs through allowlist + sandbox + replay window. Returns stdout/stderr/exitCode.",
    inputSchema: zodToJsonSchema(GuardExecArgs),
    annotations: { readOnlyHint: false, destructiveHint: true },
  },
  {
    name: "guard_spawn",
    description:
      "Defended replacement for child_process.spawn. Returns stdout/stderr SHA-256 hashes " +
      "instead of full bodies. Rejects shell:true.",
    inputSchema: zodToJsonSchema(GuardSpawnArgs),
    annotations: { readOnlyHint: false, destructiveHint: true },
  },
  {
    name: "register_allowlist",
    description:
      "Register a tool name with its allowed executable + args regex patterns. " +
      "Without registration the default-deny applies and guard_exec/guard_spawn refuse to run.",
    inputSchema: zodToJsonSchema(RegisterAllowlistArgs),
    annotations: { readOnlyHint: false, destructiveHint: false },
  },
  {
    name: "audit_source",
    description:
      "Scan a TypeScript / JavaScript path for unsanitised child_process.exec / spawn / " +
      "execFile calls and other shell-injection anti-patterns. Returns AuditFinding[] + summary.",
    inputSchema: zodToJsonSchema(AuditSourceArgs),
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  {
    name: "audit_report",
    description:
      "Format an AuditScanResult as markdown / json / sarif. Pure pass-through transformer.",
    inputSchema: zodToJsonSchema(AuditReportArgs),
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  {
    name: "replay_check",
    description:
      "Compute the canonical SHA-256 hash for an invocation and report whether the same " +
      "hash is already in the LRU sliding window.",
    inputSchema: zodToJsonSchema(ReplayCheckArgs),
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  {
    name: "sandbox_status",
    description:
      "Report the active sandbox profile + concrete limits (timeout, byte caps, fd budget, " +
      "cgroup-v2 active flag) for a registered tool.",
    inputSchema: zodToJsonSchema(SandboxStatusArgs),
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  {
    name: "trust_tier",
    description:
      "Derive the LOW / MEDIUM / HIGH / CRITICAL trust tier for a registered tool plus " +
      "improvement hints to lift it.",
    inputSchema: zodToJsonSchema(TrustTierArgs),
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
];

// ---------------------------------------------------------------------------
// Minimal zod -> JSON-Schema bridge
//
// We keep this in-tree rather than depending on `zod-to-json-schema` because
// the SDK's schema renderer also accepts a hand-rolled JSON Schema. The
// shape we emit is sufficient for the MCP Inspector + tools/list contract.
// ---------------------------------------------------------------------------

function zodToJsonSchema(schema: z.ZodTypeAny): {
  type: "object";
  properties: Record<string, object>;
  required: string[];
  additionalProperties: false;
} {
  if (!(schema instanceof z.ZodObject)) {
    throw new Error("zodToJsonSchema only handles z.object roots");
  }
  const shape = schema.shape as Record<string, z.ZodTypeAny>;
  const properties: Record<string, object> = {};
  const required: string[] = [];
  for (const [key, value] of Object.entries(shape)) {
    properties[key] = zodFieldToJson(value);
    if (!value.isOptional()) {
      required.push(key);
    }
  }
  return { type: "object", properties, required, additionalProperties: false };
}

function zodFieldToJson(value: z.ZodTypeAny): object {
  // Unwrap optional / default / nullable
  let inner: z.ZodTypeAny = value;
  while (
    inner instanceof z.ZodOptional ||
    inner instanceof z.ZodDefault ||
    inner instanceof z.ZodNullable
  ) {
    inner = inner._def.innerType as z.ZodTypeAny;
  }

  if (inner instanceof z.ZodString) return { type: "string" };
  if (inner instanceof z.ZodNumber) return { type: "number" };
  if (inner instanceof z.ZodBoolean) return { type: "boolean" };
  if (inner instanceof z.ZodEnum) {
    return { type: "string", enum: [...inner._def.values] };
  }
  if (inner instanceof z.ZodArray) {
    return { type: "array", items: zodFieldToJson(inner._def.type) };
  }
  if (inner instanceof z.ZodRecord) {
    return {
      type: "object",
      additionalProperties: zodFieldToJson(inner._def.valueType),
    };
  }
  if (inner instanceof z.ZodObject) return zodToJsonSchema(inner);
  if (inner instanceof z.ZodUnknown || inner instanceof z.ZodAny) return {};
  return {};
}

// ---------------------------------------------------------------------------
// Server state
// ---------------------------------------------------------------------------

interface ServerState {
  registry: AllowlistRegistry;
  replay: ReplayWindow;
}

export function makeState(): ServerState {
  return {
    registry: new AllowlistRegistry(),
    replay: new ReplayWindow(),
  };
}

function structuredError(err: unknown): { error: string; code?: string; meta?: unknown } {
  if (err instanceof ShellguardError) {
    return { error: err.message, code: err.code, meta: err.meta };
  }
  if (err instanceof Error) {
    return { error: err.message };
  }
  return { error: String(err) };
}

function asTextContent(value: unknown): {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
} {
  return {
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
  };
}

// ---------------------------------------------------------------------------
// Server wiring
// ---------------------------------------------------------------------------

export function createServer(state: ServerState = makeState()): Server {
  const server = new Server(
    { name: "mcp-stdio-shellguard-demo", version: VERSION },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const name = request.params.name;
    const rawArgs = request.params.arguments ?? {};
    try {
      switch (name) {
        case "guard_exec": {
          const args = GuardExecArgs.parse(rawArgs);
          const result = await guardExec(args, {
            registry: state.registry,
            replay: state.replay,
          });
          return asTextContent(result);
        }
        case "guard_spawn": {
          const args = GuardSpawnArgs.parse(rawArgs);
          const result = await guardSpawn(args, {
            registry: state.registry,
            replay: state.replay,
          });
          return asTextContent(result);
        }
        case "register_allowlist": {
          const args = RegisterAllowlistArgs.parse(rawArgs);
          const entry = state.registry.register(args);
          const tier = deriveTrustTier(state.registry, args.toolName, {
            sandboxActive: true,
            replayActive: true,
          });
          return asTextContent({
            registered: true,
            toolName: entry.toolName,
            executable: entry.executable,
            argsPatternCount: entry.argsRegex.length,
            sandboxProfile: entry.sandboxProfile,
            derivedTrustTier: tier.tier,
          });
        }
        case "audit_source": {
          const args = AuditSourceArgs.parse(rawArgs);
          const result = await scanPath(args.path, {
            ...(args.ignoreGlobs !== undefined ? { ignoreGlobs: args.ignoreGlobs } : {}),
            ...(args.severityFloor !== undefined
              ? { severityFloor: args.severityFloor }
              : {}),
          });
          return asTextContent(result);
        }
        case "audit_report": {
          const args = AuditReportArgs.parse(rawArgs);
          const findings = args.findings as Parameters<typeof renderReport>[0];
          const rendered = renderReport(findings, args.format as ReportFormat);
          return asTextContent(rendered);
        }
        case "replay_check": {
          const args = ReplayCheckArgs.parse(rawArgs);
          const hash = canonicalHash({
            executable: args.executable,
            args: args.args,
            ...(args.cwd !== undefined ? { cwd: args.cwd } : {}),
            ...(args.env !== undefined ? { env: args.env } : {}),
          });
          const result = args.record === false
            ? state.replay.peek(hash)
            : state.replay.record(hash);
          return asTextContent(result);
        }
        case "sandbox_status": {
          const args = SandboxStatusArgs.parse(rawArgs);
          const cgroup = await probeCgroupV2().catch(() => ({
            active: false,
            reason: "probe failed",
          }));
          const entry = args.toolName
            ? state.registry.get(args.toolName)
            : undefined;
          const profile = entry?.sandboxProfile ?? "standard";
          const limits = resolveLimits(profile);
          const status: SandboxStatus = {
            profile,
            timeoutMs: limits.timeoutMs,
            maxStdoutBytes: limits.maxStdoutBytes,
            maxStderrBytes: limits.maxStderrBytes,
            fdBudget: limits.fdBudget,
            cgroupActive: cgroup.active,
            ...(limits.cgroup !== undefined ? { cgroupLimits: limits.cgroup } : {}),
          };
          return asTextContent(status);
        }
        case "trust_tier": {
          const args = TrustTierArgs.parse(rawArgs);
          const tier = deriveTrustTier(state.registry, args.toolName, {
            sandboxActive: true,
            replayActive: true,
          });
          return asTextContent(tier);
        }
        default:
          return {
            content: [{ type: "text", text: `unknown tool: ${name}` }],
            isError: true,
          };
      }
    } catch (err) {
      const out = structuredError(err);
      if (
        err instanceof ShellguardDenied ||
        err instanceof ShellguardTimeout ||
        err instanceof ShellguardLimitExceeded
      ) {
        return {
          content: [{ type: "text", text: JSON.stringify(out, null, 2) }],
          isError: true,
        };
      }
      return {
        content: [{ type: "text", text: JSON.stringify(out, null, 2) }],
        isError: true,
      };
    }
  });

  return server;
}

// ---------------------------------------------------------------------------
// Entry-point
// ---------------------------------------------------------------------------

const isMainModule =
  typeof process !== "undefined" &&
  Array.isArray(process.argv) &&
  process.argv[1] !== undefined &&
  /server\.[mc]?js$/.test(process.argv[1]);

if (isMainModule) {
  const server = createServer();
  const transport = new StdioServerTransport();
  server.connect(transport).catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    // Errors at startup go to stderr — the parent must see them.
    process.stderr.write(`[shellguard] fatal: ${message}\n`);
    process.exit(1);
  });
  const shutdown = (signal: NodeJS.Signals): void => {
    process.stderr.write(`[shellguard] received ${signal}, shutting down\n`);
    server.close().finally(() => process.exit(0));
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

export type { ServerState };
