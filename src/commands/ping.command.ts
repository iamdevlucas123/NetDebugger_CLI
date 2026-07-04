import type { Command } from "commander";

import { probePing, type PingProbeData } from "../probes/ping.probe.js";
import type { ProbeResult } from "../core/types.js";

interface PingCommandOptions {
  count: string;
  timeout: string;
}

// Registers the ping command and connects CLI input to the ping probe.
export function registerPingCommand(program: Command): void {
  program
    .command("ping <host>")
    .description("Send ICMP echo requests with the platform ping command")
    .option("--count <count>", "Number of ping packets to send", "4")
    .option("--timeout <ms>", "Command timeout in milliseconds", "10000")
    .action(async (host: string, options: PingCommandOptions) => {
      const count = parsePositiveInteger(options.count, "count");
      const timeoutMs = parsePositiveInteger(options.timeout, "timeout");

      if (count === null || timeoutMs === null) {
        process.exitCode = 2;
        return;
      }

      const result = await probePing(host, { count, timeoutMs });

      renderPingResult(result);

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

// Prints the ping probe result in a compact human-readable format.
function renderPingResult(result: ProbeResult<PingProbeData>): void {
  console.log(`Host: ${result.target}`);

  if (result.status === "error") {
    console.log("Ping: failed");
    console.log(`Time: ${result.durationMs}ms`);
    console.log(`Error: ${result.error.message}`);
    return;
  }

  console.log(`Ping: ${result.data.reachable ? "reachable" : "unreachable"}`);
  console.log(`Packets: ${result.data.received}/${result.data.transmitted}`);
  console.log(`Packet loss: ${result.data.packetLossPercent}%`);
  console.log(`Average: ${formatAverage(result.data.averageMs)}`);
  console.log(`Time: ${result.durationMs}ms`);
}

// Formats optional average latency for ping output.
function formatAverage(value: number | undefined): string {
  return value !== undefined ? `${value}ms` : "unknown";
}
