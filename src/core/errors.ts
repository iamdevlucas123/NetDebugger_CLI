import type { ResultError } from "./result.js";

// Defines the stable error codes used by diagnostics, tests, and JSON output.
export type NetDebuggerErrorCode =
  | "DNS_ERROR"
  | "TCP_CONNECTION_ERROR"
  | "TLS_HANDSHAKE_ERROR"
  | "HTTP_REQUEST_ERROR"
  | "TIMEOUT_ERROR"
  | "INVALID_URL_ERROR";

export interface NetDebuggerErrorOptions {
  target?: string;
  details?: Record<string, unknown>;
  cause?: unknown;
}

// Base error for known NetDebugger domain failures with stable diagnostic codes.
export class NetDebuggerError extends Error {
  readonly code: NetDebuggerErrorCode;
  readonly target?: string;
  readonly details?: Record<string, unknown>;

  constructor(
    code: NetDebuggerErrorCode,
    message: string,
    options?: NetDebuggerErrorOptions,
  ) {
    if (options && "cause" in options) {
      super(message, { cause: options.cause });
    } else {
      super(message);
    }

    this.name = new.target.name;
    this.code = code;

    if (options?.target !== undefined) {
      this.target = options.target;
    }

    if (options?.details !== undefined) {
      this.details = options.details;
    }

    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// Represents DNS resolution failures for a hostname or domain.
export class DnsError extends NetDebuggerError {
  constructor(message: string, options?: NetDebuggerErrorOptions) {
    super("DNS_ERROR", message, options);
  }
}

// Represents failures while opening or establishing a TCP connection.
export class TcpConnectionError extends NetDebuggerError {
  constructor(message: string, options?: NetDebuggerErrorOptions) {
    super("TCP_CONNECTION_ERROR", message, options);
  }
}

// Represents TLS handshake, certificate, or protocol negotiation failures.
export class TlsHandshakeError extends NetDebuggerError {
  constructor(message: string, options?: NetDebuggerErrorOptions) {
    super("TLS_HANDSHAKE_ERROR", message, options);
  }
}

// Represents HTTP request failures that happen before a complete response is available.
export class HttpRequestError extends NetDebuggerError {
  constructor(message: string, options?: NetDebuggerErrorOptions) {
    super("HTTP_REQUEST_ERROR", message, options);
  }
}

// Represents operations that exceed their configured timeout.
export class TimeoutError extends NetDebuggerError {
  constructor(message: string, options?: NetDebuggerErrorOptions) {
    super("TIMEOUT_ERROR", message, options);
  }
}

// Represents user input that cannot be normalized into a valid URL or target.
export class InvalidUrlError extends NetDebuggerError {
  constructor(message: string, options?: NetDebuggerErrorOptions) {
    super("INVALID_URL_ERROR", message, options);
  }
}

// Checks whether an unknown value is a NetDebugger domain error.
export function isNetDebuggerError(
  error: unknown,
): error is NetDebuggerError {
  return error instanceof NetDebuggerError;
}

// Converts known and unknown thrown values into the serializable ResultError shape.
export function toResultError(error: unknown): ResultError {
  if (isNetDebuggerError(error)) {
    const details: Record<string, unknown> = {};

    if (error.target !== undefined) {
      details.target = error.target;
    }

    if (error.details !== undefined) {
      Object.assign(details, error.details);
    }

    if (Object.keys(details).length > 0) {
      return {
        code: error.code,
        message: error.message,
        details,
      };
    }

    return {
      code: error.code,
      message: error.message,
    };
  }

  if (error instanceof Error) {
    return {
      code: "UNKNOWN_ERROR",
      message: error.message,
    };
  }

  return {
    code: "UNKNOWN_ERROR",
    message: "Unknown error",
  };
}
