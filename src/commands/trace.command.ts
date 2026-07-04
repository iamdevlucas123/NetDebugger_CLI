import type { Command } from "commander";

import {
  probeTraceroute,
  type TracerouteProbeData,
} from "../probes/traceroute.probe.js";
import type { ProbeResult } from "../core/types.js";

interface TraceCommandOptions {
  timeout: string;
}

// Registers the trace command and connects CLI input to the traceroute probe.
export function registerTraceCommand(program: Command): void {
  program
    .command("trace <host>")
    .description("Run traceroute or tracert as a separate slow network diagnostic")
    .option("--timeout <ms>", "Command timeout in milliseconds", "30000")
    .action(async (host: string, options: TraceCommandOptions) => {
      const timeoutMs = parsePositiveInteger(options.timeout, "timeout");

      if (timeoutMs === null) {
        process.exitCode = 2;
        return;
      }

      const result = await probeTraceroute(host, { timeoutMs });

      renderTraceResult(result);

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

// Prints the traceroute probe result in a compact human-readable format.
function renderTraceResult(result: ProbeResult<TracerouteProbeData>): void {
  console.log(`Host: ${result.target}`);

  if (result.status === "error") {
    console.log("Trace: failed");
    console.log(`Time: ${result.durationMs}ms`);
    console.log(`Error: ${result.error.message}`);
    return;
  }

  console.log("Trace: completed");
  console.log(`Hops: ${result.data.hops.length}`);
  console.log(`Time: ${result.durationMs}ms`);

  for (const hop of result.data.hops) {
    console.log(`${hop.hop}: ${hop.output}`);
  }
}
