import type { ResultError } from "./result.js";

//The function can have one or more error messsages
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

export class DnsError extends NetDebuggerError {
  constructor(message: string, options?: NetDebuggerErrorOptions) {
    super("DNS_ERROR", message, options);
  }
}

export class TcpConnectionError extends NetDebuggerError {
  constructor(message: string, options?: NetDebuggerErrorOptions) {
    super("TCP_CONNECTION_ERROR", message, options);
  }
}

export class TlsHandshakeError extends NetDebuggerError {
  constructor(message: string, options?: NetDebuggerErrorOptions) {
    super("TLS_HANDSHAKE_ERROR", message, options);
  }
}

export class HttpRequestError extends NetDebuggerError {
  constructor(message: string, options?: NetDebuggerErrorOptions) {
    super("HTTP_REQUEST_ERROR", message, options);
  }
}

export class TimeoutError extends NetDebuggerError {
  constructor(message: string, options?: NetDebuggerErrorOptions) {
    super("TIMEOUT_ERROR", message, options);
  }
}

export class InvalidUrlError extends NetDebuggerError {
  constructor(message: string, options?: NetDebuggerErrorOptions) {
    super("INVALID_URL_ERROR", message, options);
  }
}

export function isNetDebuggerError(
  error: unknown,
): error is NetDebuggerError {
  return error instanceof NetDebuggerError;
}

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
