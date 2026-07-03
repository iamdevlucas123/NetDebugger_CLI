import type { Command } from "commander";

import { probeHttp } from "../probes/http.probe.js";
import type { HttpProbeData, ProbeResult } from "../core/types.js";

interface HttpCommandOptions {
  timeout: string;
  maxRedirects: string;
}

// Registers the http command and connects CLI input to the HTTP probe.
export function registerHttpCommand(program: Command): void {
  program
    .command("http <url>")
    .description("Request a URL and inspect status, headers, redirects, and timing")
    .option("--timeout <ms>", "Request timeout in milliseconds", "5000")
    .option("--max-redirects <count>", "Maximum redirects to follow", "5")
    .action(async (url: string, options: HttpCommandOptions) => {
      const timeoutMs = parsePositiveInteger(options.timeout, "timeout");
      const maxRedirects = parseNonNegativeInteger(
        options.maxRedirects,
        "max redirects",
      );

      if (timeoutMs === null || maxRedirects === null) {
        process.exitCode = 2;
        return;
      }

      const result = await probeHttp(url, { timeoutMs, maxRedirects });

      renderHttpResult(result);

      if (result.status === "error") {
        process.exitCode = 1;
      }
    });
}

// Parses a positive integer CLI option.
function parsePositiveInteger(value: string, label: string): number | null {
  const parsed = Number(value);

  if (!Number.isInteger(parsed) || parsed < 1) {
    console.error(`Invalid ${label}. Use a positive integer.`);
    return null;
  }

  return parsed;
}

// Parses a non-negative integer CLI option.
function parseNonNegativeInteger(value: string, label: string): number | null {
  const parsed = Number(value);

  if (!Number.isInteger(parsed) || parsed < 0) {
    console.error(`Invalid ${label}. Use zero or a positive integer.`);
    return null;
  }

  return parsed;
}

// Prints the HTTP probe result in a compact human-readable format.
function renderHttpResult(result: ProbeResult<HttpProbeData>): void {
  if (result.status === "error") {
    console.log("HTTP: ERROR");
    console.log(`Total time: ${result.durationMs}ms`);
    console.log(`Error: ${result.error.message}`);
    return;
  }

  console.log(`HTTP: ${result.data.statusCode} ${result.data.statusText ?? ""}`.trimEnd());
  console.log(`Total time: ${result.durationMs}ms`);
  console.log(`Redirects: ${result.data.redirects.length}`);
  console.log(`Content-Type: ${getHeader(result.data, "content-type")}`);
  console.log(`Server: ${getHeader(result.data, "server")}`);
}

// Reads a response header as a printable string.
function getHeader(data: HttpProbeData, name: string): string {
  const value = data.headers[name.toLowerCase()];

  if (Array.isArray(value)) {
    return value.join(", ");
  }

  return value ?? "none";
}
