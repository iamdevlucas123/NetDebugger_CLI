import type { Command } from "commander";

import { InvalidUrlError } from "../core/errors.js";
import { renderDoctorConsoleReport } from "../output/console.reporter.js";
import { renderDoctorJsonReport } from "../output/json.reporter.js";
import { runDoctor } from "../services/doctor.service.js";

interface DoctorCommandOptions {
  timeout: string;
  runs: string;
  json?: boolean;
  verbose?: boolean;
}

// Registers the doctor command and connects CLI input to the doctor service.
export function registerDoctorCommand(program: Command): void {
  program
    .command("doctor <url>")
    .description("Run a full DNS, TCP, TLS, HTTP, headers, latency, and diagnosis check")
    .option("--timeout <ms>", "Per-step timeout in milliseconds", "5000")
    .option("--runs <count>", "Number of HTTP samples for latency analysis", "1")
    .option("--json", "Print the full structured diagnostic report")
    .option("--verbose", "Print analyzer findings in console output")
    .action(async (url: string, options: DoctorCommandOptions) => {
      const timeoutMs = parsePositiveInteger(options.timeout, "timeout");
      const runs = parsePositiveInteger(options.runs, "runs");

      if (timeoutMs === null || runs === null) {
        process.exitCode = 2;
        return;
      }

      try {
        const report = await runDoctor(url, {
          timeoutMs,
          runs,
          verbose: Boolean(options.verbose),
        });

        if (options.json === true) {
          console.log(renderDoctorJsonReport(report));
        } else {
          console.log(
            renderDoctorConsoleReport(report, {
              verbose: Boolean(options.verbose),
            }),
          );
        }

        if (!report.result.ok) {
          process.exitCode = 1;
        }
      } catch (error) {
        renderDoctorError(error);
        process.exitCode = error instanceof InvalidUrlError ? 2 : 3;
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

// Prints doctor command failures that happen before a report is produced.
function renderDoctorError(error: unknown): void {
  if (error instanceof Error) {
    console.error(`Doctor error: ${error.message}`);
    return;
  }

  console.error("Doctor error: Unexpected failure.");
}
