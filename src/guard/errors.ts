/**
 * Custom error classes for shellguard. All errors carry a stable
 * `code` field so callers can switch on it programmatically without
 * relying on message strings.
 */

export type ShellguardErrorCode =
  | "SHELLGUARD_DENIED"
  | "SHELLGUARD_TIMEOUT"
  | "SHELLGUARD_STDOUT_LIMIT"
  | "SHELLGUARD_STDERR_LIMIT"
  | "SHELLGUARD_FD_BUDGET"
  | "SHELLGUARD_SHELL_FORBIDDEN"
  | "SHELLGUARD_INVALID_REGISTRATION";

export class ShellguardError extends Error {
  readonly code: ShellguardErrorCode;
  readonly meta: Record<string, unknown>;

  constructor(
    code: ShellguardErrorCode,
    message: string,
    meta: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "ShellguardError";
    this.code = code;
    this.meta = meta;
  }
}

export class ShellguardDenied extends ShellguardError {
  constructor(message: string, meta: Record<string, unknown> = {}) {
    super("SHELLGUARD_DENIED", message, meta);
    this.name = "ShellguardDenied";
  }
}

export class ShellguardTimeout extends ShellguardError {
  constructor(message: string, meta: Record<string, unknown> = {}) {
    super("SHELLGUARD_TIMEOUT", message, meta);
    this.name = "ShellguardTimeout";
  }
}

export class ShellguardLimitExceeded extends ShellguardError {
  constructor(
    code: "SHELLGUARD_STDOUT_LIMIT" | "SHELLGUARD_STDERR_LIMIT" | "SHELLGUARD_FD_BUDGET",
    message: string,
    meta: Record<string, unknown> = {},
  ) {
    super(code, message, meta);
    this.name = "ShellguardLimitExceeded";
  }
}
