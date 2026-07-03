import { Socket } from "node:net";

import { TcpConnectionError, TimeoutError, toResultError } from "../core/errors.js";
import {
  createErrorResult,
  createOkResult,
  type ProbeResult,
} from "../core/result.js";
import type { TcpProbeData } from "../core/types.js";

interface TcpProbeOptions {
  timeoutMs?: number;
}

interface TcpProbeDependencies {
  createSocket?: () => Socket;
  now?: () => number;
}

// Tests whether a TCP port accepts connections and returns the standard probe result.
export function connectTcp(
  host: string,
  port: number,
  options: TcpProbeOptions = {},
  dependencies: TcpProbeDependencies = {},
): Promise<ProbeResult<TcpProbeData>> {
  const hostname = host.trim();
  const target = `${hostname}:${port}`;
  const timeoutMs = options.timeoutMs ?? 5000;
  const now = dependencies.now ?? Date.now;
  const startedAt = now();
  const socket = dependencies.createSocket?.() ?? new Socket();

  return new Promise((resolve) => {
    let settled = false;

    // Completes the probe once and guarantees the socket is cleaned up.
    function settle(result: ProbeResult<TcpProbeData>): void {
      if (settled) {
        return;
      }

      settled = true;
      socket.destroy();
      resolve(result);
    }

    // Calculates the elapsed connection time for success, error, or timeout.
    function getDurationMs(): number {
      return Math.max(0, Math.round(now() - startedAt));
    }

    socket.setTimeout(timeoutMs, () => {
      const error = new TimeoutError(`TCP connection timed out for ${target}`, {
        target,
        details: {
          operation: "tcp.connect",
          timeoutMs,
        },
      });

      settle(
        createErrorResult({
          target,
          durationMs: getDurationMs(),
          error: toResultError(error),
        }),
      );
    });

    socket.once("connect", () => {
      settle(
        createOkResult({
          target,
          durationMs: getDurationMs(),
          data: {
            hostname,
            port,
            connected: true,
            ...(socket.remoteAddress !== undefined
              ? { remoteAddress: socket.remoteAddress }
              : {}),
            ...(socket.remoteFamily !== undefined
              ? { remoteFamily: socket.remoteFamily }
              : {}),
          },
        }),
      );
    });

    socket.once("error", (cause: Error) => {
      const error = new TcpConnectionError(
        `TCP connection failed for ${target}`,
        {
          target,
          cause,
          details: {
            cause: cause.message,
          },
        },
      );

      settle(
        createErrorResult({
          target,
          durationMs: getDurationMs(),
          error: toResultError(error),
        }),
      );
    });

    socket.once("close", () => {
      if (settled) {
        return;
      }

      const error = new TcpConnectionError(
        `TCP connection closed before connecting to ${target}`,
        { target },
      );

      settle(
        createErrorResult({
          target,
          durationMs: getDurationMs(),
          error: toResultError(error),
        }),
      );
    });

    socket.connect({ host: hostname, port });
  });
}
