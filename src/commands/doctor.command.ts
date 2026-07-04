import { writeFile } from "node:fs/promises";
import type { Command } from "commander";

import { InvalidUrlError } from "../core/errors.js";
import type { ProbeResult } from "../core/types.js";
import { renderDoctorConsoleReport } from "../output/console.reporter.js";
import { renderDoctorJsonReport } from "../output/json.reporter.js";
import {
  probeTraceroute,
  type TracerouteProbeData,
} from "../probes/traceroute.probe.js";
import { runDoctor } from "../services/doctor.service.js";

interface DoctorCommandOptions {
  timeout: string;
  runs: string;
  timeout5000?: boolean;
  runs10?: boolean;
  runs20?: boolean;
  json?: boolean;
  verbose?: boolean;
  headers?: boolean;
  trace?: boolean;
  color?: boolean;
  output?: string;
}

// Registers the doctor command and connects CLI input to the doctor service.
export function registerDoctorCommand(program: Command): void {
  program
    .command("doctor <url>")
    .description("Run a full DNS, TCP, TLS, HTTP, headers, latency, and diagnosis check")
    .option("--timeout <ms>", "Per-step timeout in milliseconds", "5000")
    .option("--timeout5000", "Shortcut for --timeout 5000")
    .option("--runs <count>", "Number of HTTP samples for latency analysis", "1")
    .option("--runs10", "Shortcut for --runs 10")
    .option("--runs20", "Shortcut for --runs 20")
    .option("--json", "Print the full structured diagnostic report")
    .option("--verbose", "Print analyzer findings in console output")
    .option("--headers", "Print selected HTTP response headers")
    .option("--trace", "Run traceroute after doctor and include the result")
    .option("--output <file>", "Write the rendered report to a file")
    .option("--no-color", "Disable color output")
    .action(async (url: string, options: DoctorCommandOptions) => {
      const timeoutMs = parsePositiveInteger(
        options.timeout5000 === true ? "5000" : options.timeout,
        "timeout",
      );
      const runs = parsePositiveInteger(
        getRunsValue(options),
        "runs",
      );

      if (timeoutMs === null || runs === null) {
        process.exitCode = 2;
        return;
      }

      try {
        applyColorPreference(options);
        warnWhenProtocolIsMissing(url, Boolean(options.json));

        const report = await runDoctor(url, {
          timeoutMs,
          runs,
          verbose: Boolean(options.verbose),
        });
        const traceResult =
          options.trace === true
            ? await probeTraceroute(report.result.target.hostname, { timeoutMs })
            : undefined;
        const renderedOutput = renderDoctorOutput(report, options, traceResult);

        console.log(renderedOutput);
        await writeOutputFile(options.output, renderedOutput);

        if (!report.result.ok) {
          process.exitCode = 1;
        }
      } catch (error) {
        renderDoctorError(error);
        process.exitCode = error instanceof InvalidUrlError ? 2 : 3;
      }
    });
}

// Chooses the run count from normal or shortcut options.
function getRunsValue(options: DoctorCommandOptions): string {
  if (options.runs20 === true) {
    return "20";
  }

  if (options.runs10 === true) {
    return "10";
  }

  return options.runs;
}

// Applies CLI color preference for libraries that respect NO_COLOR.
function applyColorPreference(options: DoctorCommandOptions): void {
  if (options.color === false) {
    process.env.NO_COLOR = "1";
  }
}

// Warns users when doctor automatically adds the HTTPS protocol.
function warnWhenProtocolIsMissing(input: string, jsonOutput: boolean): void {
  if (jsonOutput || /^[a-z][a-z\d+\-.]*:\/\//i.test(input.trim())) {
    return;
  }

  console.error("No protocol provided. Using https:// by default.");
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

// Renders doctor output in JSON or console form.
function renderDoctorOutput(
  report: Awaited<ReturnType<typeof runDoctor>>,
  options: DoctorCommandOptions,
  traceResult: ProbeResult<TracerouteProbeData> | undefined,
): string {
  if (options.json === true) {
    const payload = JSON.parse(renderDoctorJsonReport(report)) as Record<
      string,
      unknown
    >;

    if (traceResult !== undefined) {
      payload.trace = traceResult;
    }

    return JSON.stringify(payload, null, 2);
  }

  const sections = [
    renderDoctorConsoleReport(report, {
      verbose: Boolean(options.verbose),
      includeHeaders: Boolean(options.headers),
    }),
  ];

  if (traceResult !== undefined) {
    sections.push(renderTraceSummary(traceResult));
  }

  return sections.join("\n\n");
}

// Renders a compact traceroute summary for doctor --trace.
function renderTraceSummary(result: ProbeResult<TracerouteProbeData>): string {
  if (result.status === "error") {
    return [
      "Trace:",
      "Status: ERROR",
      `Error: ${result.error.message}`,
      "Possible causes:",
      "- Traceroute is blocked by the network",
      "- The command is unavailable on this system",
      "- The target is not reachable",
      "- The operation timed out",
    ].join("\n");
  }

  return [
    "Trace:",
    "Status: OK",
    `Hops: ${result.data.hops.length}`,
    `Time: ${result.durationMs}ms`,
  ].join("\n");
}

// Writes rendered output to a file when requested.
async function writeOutputFile(
  outputPath: string | undefined,
  content: string,
): Promise<void> {
  if (outputPath === undefined) {
    return;
  }

  await writeFile(outputPath, `${content}\n`, "utf8");
}

// Prints doctor command failures that happen before a report is produced.
function renderDoctorError(error: unknown): void {
  if (error instanceof InvalidUrlError) {
    console.error("Invalid URL.");
    console.error("Possible fixes:");
    console.error("- Use a valid hostname, for example google.com");
    console.error("- Use http:// or https:// when you need a specific protocol");
    console.error("- Check for spaces or unsupported URL characters");
    console.error(`Details: ${error.message}`);
    return;
  }

  if (error instanceof Error) {
    console.error("Doctor failed.");
    console.error("Possible causes:");
    console.error("- Network operation failed unexpectedly");
    console.error("- The target is unreachable");
    console.error("- A local system command or permission failed");
    console.error(`Details: ${error.message}`);
    return;
  }

  console.error("Doctor failed with an unexpected error.");
}
