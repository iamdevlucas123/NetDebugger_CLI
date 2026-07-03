import type { Command } from "commander";

import { connectTcp } from "../probes/tcp.probe.js";
import type { ProbeResult, TcpProbeData } from "../core/types.js";

interface TcpCommandOptions {
  port: string;
  timeout: string;
}

// Registers the tcp command and connects CLI input to the TCP probe.
export function registerTcpCommand(program: Command): void {
  program
    .command("tcp <host>")
    .description("Test whether a TCP port is open")
    .requiredOption("--port <port>", "TCP port to connect to")
    .option("--timeout <ms>", "Connection timeout in milliseconds", "5000")
    .action(async (host: string, options: TcpCommandOptions) => {
      const port = parsePort(options.port);
      const timeoutMs = parseTimeout(options.timeout);

      if (port === null || timeoutMs === null) {
        process.exitCode = 2;
        return;
      }

      const result = await connectTcp(host, port, { timeoutMs });

      renderTcpResult(result, host, port);

      if (result.status === "error") {
        process.exitCode = 1;
      }
    });
}

// Parses a CLI port option into a valid TCP port number.
function parsePort(value: string): number | null {
  const port = Number(value);

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error("Invalid port. Use a number between 1 and 65535.");
    return null;
  }

  return port;
}

// Parses a CLI timeout option into a positive millisecond value.
function parseTimeout(value: string): number | null {
  const timeoutMs = Number(value);

  if (!Number.isInteger(timeoutMs) || timeoutMs < 1) {
    console.error("Invalid timeout. Use a positive number of milliseconds.");
    return null;
  }

  return timeoutMs;
}

// Prints the TCP probe result in a compact human-readable format.
function renderTcpResult(
  result: ProbeResult<TcpProbeData>,
  host: string,
  port: number,
): void {
  console.log(`Host: ${host}`);
  console.log(`Port: ${port}`);

  if (result.status === "ok") {
    console.log("TCP: open");
    console.log(`Connect time: ${result.durationMs}ms`);
    return;
  }

  console.log(`TCP: ${formatTcpError(result.error.code)}`);
  console.log(`Connect time: ${result.durationMs}ms`);
  console.log(`Error: ${result.error.message}`);
}

// Maps structured error codes to concise TCP status text.
function formatTcpError(errorCode: string): "closed" | "timeout" {
  return errorCode === "TIMEOUT_ERROR" ? "timeout" : "closed";
}
