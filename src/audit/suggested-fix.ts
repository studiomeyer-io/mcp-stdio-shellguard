/**
 * Suggested-fix strings keyed by audit pattern id.
 */

export type AuditPatternId =
  | "exec_dynamic_string"
  | "exec_sync_dynamic_string"
  | "spawn_dynamic_file_args"
  | "spawn_literal_dynamic_args"
  | "exec_template_literal_with_input"
  | "shell_true_option"
  | "exec_file_dynamic"
  | "eval_near_child_process"
  | "function_constructor_near_child_process"
  | "os_system_equivalent"
  | "unbounded_buffer"
  | "missing_timeout";

export const SUGGESTED_FIX: Record<AuditPatternId, string> = {
  exec_dynamic_string:
    "Replace child_process.exec(<dynamic-string>) with " +
    "guard_exec({ toolName, command, args }) and call register_allowlist " +
    "first. Never concatenate user input into the command string.",
  exec_sync_dynamic_string:
    "Replace child_process.execSync(<dynamic-string>) with the synchronous " +
    "wrapper guard_execSync(...) — same allowlist semantics.",
  spawn_dynamic_file_args:
    "Both file and args are dynamic. Replace with guard_spawn({ toolName, " +
    "file, args }) and register an allowlist with strict argsPatterns.",
  spawn_literal_dynamic_args:
    "Executable is a literal but args are dynamic. Add an argsPatterns " +
    "regex array to the registered allowlist entry.",
  exec_template_literal_with_input:
    "Template-literal with user input is a shell-injection vector. " +
    "Move the variable into args[]: guard_exec({ command: 'git', args: ['log', userInput] }).",
  shell_true_option:
    "Drop `shell: true` and use args[] vector. The guard rejects shell:true " +
    "explicitly because it re-enables string-concatenation attack surface.",
  exec_file_dynamic:
    "child_process.execFile with dynamic file is the same risk class as spawn. " +
    "Use guard_spawn(...) with an allowlist.",
  eval_near_child_process:
    "Eliminate eval(...). If you need dynamic dispatch, use a switch over a " +
    "fixed table of registered tools.",
  function_constructor_near_child_process:
    "Eliminate `new Function(...)` next to child_process — that is dynamic " +
    "code execution that bypasses static analysis.",
  os_system_equivalent:
    "Wrap deno/bun-style `os.system` calls behind guard_exec. The platform " +
    "shim does not change the threat model.",
  unbounded_buffer:
    "Add `maxStdoutBytes` and `maxStderrBytes` (or rely on a sandbox " +
    "profile). Unbounded buffers are a memory-DoS surface.",
  missing_timeout:
    "Add `timeoutMs` (or rely on a sandbox profile). A long-running spawn " +
    "without a wall-clock timeout is a hang surface.",
};
