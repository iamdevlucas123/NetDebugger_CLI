import type { Command } from "commander";

import { InvalidUrlError } from "../core/errors.js";
import type { Finding } from "../core/types.js";
import {
  runDoctor,
  type DoctorReport,
} from "../services/doctor.service.js";

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
          console.log(JSON.stringify(report, null, 2));
        } else {
          renderDoctorReport(report, Boolean(options.verbose));
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

// Prints a compact human-readable doctor report.
function renderDoctorReport(report: DoctorReport, verbose: boolean): void {
  const { result } = report;
  const http = result.probes.http;

  console.log(`Doctor: ${result.ok ? "OK" : "ISSUES"}`);
  console.log(`URL: ${result.target.href ?? result.target.input}`);
  console.log(`DNS: ${formatProbeStatus(result.probes.dns?.status)}`);
  console.log(`TCP: ${formatProbeStatus(result.probes.tcp?.status)}`);
  console.log(
    `TLS: ${result.target.expectsTls ? formatProbeStatus(result.probes.tls?.status) : "SKIPPED"}`,
  );
  console.log(
    `HTTP: ${
      http?.status === "ok"
        ? `${http.data.statusCode} ${http.data.statusText ?? ""}`.trimEnd()
        : formatProbeStatus(http?.status)
    }`,
  );
  console.log(`Total time: ${result.durationMs}ms`);
  console.log(`Runs: ${report.httpRuns.length}`);

  if (result.latency !== undefined) {
    console.log(
      `Latency avg/p95: ${result.latency.averageMs}ms/${result.latency.p95Ms}ms`,
    );
  }

  renderFindingSummary(result.findings, verbose);
}

// Converts a probe status into a printable command status.
function formatProbeStatus(status: "ok" | "error" | undefined): string {
  if (status === "ok") {
    return "OK";
  }

  if (status === "error") {
    return "ERROR";
  }

  return "SKIPPED";
}

// Prints important findings and optionally all findings in verbose mode.
function renderFindingSummary(findings: Finding[], verbose: boolean): void {
  const visibleFindings = verbose
    ? findings
    : findings.filter((finding) => finding.severity !== "info");

  console.log(`Findings: ${visibleFindings.length}`);

  for (const finding of visibleFindings) {
    console.log(
      `- [${finding.severity}] ${finding.code}: ${finding.message}`,
    );
  }
}

// Prints doctor command failures that happen before a report is produced.
function renderDoctorError(error: unknown): void {
  if (error instanceof Error) {
    console.error(`Doctor error: ${error.message}`);
    return;
  }

  console.error("Doctor error: Unexpected failure.");
}
