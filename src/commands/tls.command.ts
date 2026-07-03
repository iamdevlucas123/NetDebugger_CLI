import type { Command } from "commander";

import { analyzeTlsCertificate } from "../analyzers/tls.analyzer.js";
import { probeTls } from "../probes/tls.probe.js";
import type { ProbeResult, TlsProbeData } from "../core/types.js";

interface TlsCommandOptions {
  port?: string;
  timeout: string;
}

interface TlsTarget {
  host: string;
  port: number;
}

// Registers the tls command and connects CLI input to the TLS probe and analyzer.
export function registerTlsCommand(program: Command): void {
  program
    .command("tls <target>")
    .description("Inspect TLS handshake and certificate details")
    .option("--port <port>", "TLS port to connect to")
    .option("--timeout <ms>", "Connection timeout in milliseconds", "5000")
    .action(async (target: string, options: TlsCommandOptions) => {
      const parsedTarget = parseTlsTarget(target, options.port);
      const timeoutMs = parseTimeout(options.timeout);

      if (parsedTarget === null || timeoutMs === null) {
        process.exitCode = 2;
        return;
      }

      const result = await probeTls(parsedTarget.host, parsedTarget.port, {
        timeoutMs,
      });

      renderTlsResult(result);

      if (result.status === "error") {
        process.exitCode = 1;
      }
    });
}

// Parses a URL or hostname into a TLS host and port.
function parseTlsTarget(input: string, portOption?: string): TlsTarget | null {
  const parsedPort = portOption !== undefined ? parsePort(portOption) : null;

  if (portOption !== undefined && parsedPort === null) {
    return null;
  }

  try {
    const url = input.includes("://")
      ? new URL(input)
      : new URL(`https://${input}`);

    if (url.protocol !== "https:") {
      console.error("Invalid TLS target. Use an https URL or hostname.");
      return null;
    }

    return {
      host: url.hostname,
      port: parsedPort ?? (url.port ? Number(url.port) : 443),
    };
  } catch {
    console.error("Invalid TLS target. Use an https URL or hostname.");
    return null;
  }
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

// Prints the TLS probe result and certificate analysis in a compact format.
function renderTlsResult(result: ProbeResult<TlsProbeData>): void {
  if (result.status === "error") {
    console.log("TLS: ERROR");
    console.log(`Error: ${result.error.message}`);
    return;
  }

  const analysis = analyzeTlsCertificate(result.data);
  const certificate = result.data.certificate;

  console.log("TLS: OK");
  console.log(`Version: ${result.data.protocol ?? "unknown"}`);
  console.log(`Cipher: ${result.data.cipher ?? "unknown"}`);
  console.log(`Issuer: ${certificate?.issuer ?? "unknown"}`);
  console.log(`Subject: ${certificate?.subject ?? "unknown"}`);
  console.log(`Expires: ${formatDate(certificate?.validTo)}`);
  console.log(`Days left: ${analysis.daysLeft ?? "unknown"}`);

  for (const finding of analysis.findings) {
    console.log(`Warning: ${finding.message}`);
  }
}

// Formats certificate dates as YYYY-MM-DD when possible.
function formatDate(value: string | undefined): string {
  if (value === undefined) {
    return "unknown";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toISOString().slice(0, 10);
}
