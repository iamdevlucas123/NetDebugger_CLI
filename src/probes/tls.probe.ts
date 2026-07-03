import { connect, type ConnectionOptions, type PeerCertificate } from "node:tls";
import type { EventEmitter } from "node:events";

import {
  TimeoutError,
  TlsHandshakeError,
  toResultError,
} from "../core/errors.js";
import {
  createErrorResult,
  createOkResult,
  type ProbeResult,
} from "../core/result.js";
import type { TlsCertificateInfo, TlsProbeData } from "../core/types.js";

interface TlsProbeOptions {
  timeoutMs?: number;
}

interface TlsSocketLike extends EventEmitter {
  authorized: boolean;
  authorizationError?: Error | string;
  getProtocol(): string | null;
  getCipher(): { name?: string; standardName?: string };
  getPeerCertificate(detailed: true): PeerCertificate;
  setTimeout(timeoutMs: number, callback: () => void): this;
  destroy(): void;
}

type TlsConnect = (
  options: ConnectionOptions,
  callback: () => void,
) => TlsSocketLike;

interface TlsProbeDependencies {
  connect?: TlsConnect;
  now?: () => number;
}

// Performs a TLS handshake and returns protocol, cipher, and certificate details.
export function probeTls(
  host: string,
  port = 443,
  options: TlsProbeOptions = {},
  dependencies: TlsProbeDependencies = {},
): Promise<ProbeResult<TlsProbeData>> {
  const hostname = host.trim();
  const target = `${hostname}:${port}`;
  const timeoutMs = options.timeoutMs ?? 5000;
  const now = dependencies.now ?? Date.now;
  const startedAt = now();
  const connectTls = dependencies.connect ?? connectWithNodeTls;

  return new Promise((resolve) => {
    let settled = false;

    // Completes the TLS probe once and closes the socket.
    function settle(result: ProbeResult<TlsProbeData>, socket: TlsSocketLike): void {
      if (settled) {
        return;
      }

      settled = true;
      socket.destroy();
      resolve(result);
    }

    // Calculates elapsed time for TLS handshake attempts.
    function getDurationMs(): number {
      return Math.max(0, Math.round(now() - startedAt));
    }

    const socket = connectTls(
      {
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized: false,
      },
      () => {
        settle(
          createOkResult({
            target,
            durationMs: getDurationMs(),
            data: buildTlsData(hostname, port, socket),
          }),
          socket,
        );
      },
    );

    socket.setTimeout(timeoutMs, () => {
      const error = new TimeoutError(`TLS handshake timed out for ${target}`, {
        target,
        details: {
          operation: "tls.connect",
          timeoutMs,
        },
      });

      settle(
        createErrorResult({
          target,
          durationMs: getDurationMs(),
          error: toResultError(error),
        }),
        socket,
      );
    });

    socket.once("error", (cause: Error) => {
      const error = new TlsHandshakeError(`TLS handshake failed for ${target}`, {
        target,
        cause,
        details: {
          cause: cause.message,
        },
      });

      settle(
        createErrorResult({
          target,
          durationMs: getDurationMs(),
          error: toResultError(error),
        }),
        socket,
      );
    });
  });
}

// Wraps Node's overloaded tls.connect API behind a single testable signature.
function connectWithNodeTls(
  options: ConnectionOptions,
  callback: () => void,
): TlsSocketLike {
  return connect(options, callback) as TlsSocketLike;
}

// Builds serializable TLS probe data from a connected TLS socket.
function buildTlsData(
  hostname: string,
  port: number,
  socket: TlsSocketLike,
): TlsProbeData {
  const data: TlsProbeData = {
    hostname,
    port,
    authorized: socket.authorized,
    certificate: formatCertificate(socket.getPeerCertificate(true)),
  };

  if (socket.authorizationError !== undefined) {
    data.authorizationError = formatAuthorizationError(socket.authorizationError);
  }

  const protocol = socket.getProtocol();

  if (protocol !== null) {
    data.protocol = protocol;
  }

  const cipher = getCipherName(socket);

  if (cipher !== undefined) {
    data.cipher = cipher;
  }

  return data;
}

// Extracts a readable cipher name from the connected TLS socket.
function getCipherName(socket: TlsSocketLike): string | undefined {
  const cipher = socket.getCipher();

  return cipher.standardName ?? cipher.name;
}

// Converts Node certificate metadata into the project's serializable shape.
function formatCertificate(certificate: PeerCertificate): TlsCertificateInfo {
  return {
    ...(certificate.subject !== undefined
      ? { subject: formatCertificateName(certificate.subject) }
      : {}),
    ...(certificate.issuer !== undefined
      ? { issuer: formatCertificateName(certificate.issuer) }
      : {}),
    ...(certificate.valid_from !== undefined
      ? { validFrom: certificate.valid_from }
      : {}),
    ...(certificate.valid_to !== undefined ? { validTo: certificate.valid_to } : {}),
    ...(certificate.fingerprint !== undefined
      ? { fingerprint: certificate.fingerprint }
      : {}),
    ...(typeof certificate.subjectaltname === "string"
      ? { subjectAltNames: certificate.subjectaltname.split(", ") }
      : {}),
  };
}

// Formats certificate subject and issuer objects into compact strings.
function formatCertificateName(value: PeerCertificate["subject"]): string {
  if (typeof value === "string") {
    return value;
  }

  if (value === undefined) {
    return "unknown";
  }

  return Object.values(value).filter(Boolean).join(", ");
}

// Converts TLS authorization errors into readable text.
function formatAuthorizationError(error: Error | string): string {
  return error instanceof Error ? error.message : error;
}
