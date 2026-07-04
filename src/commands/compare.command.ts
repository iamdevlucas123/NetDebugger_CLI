import type { Command } from "commander";

import { InvalidUrlError } from "../core/errors.js";
import type { HttpProbeData, ProbeResult, TlsProbeData } from "../core/types.js";
import { runDoctor, type DoctorReport } from "../services/doctor.service.js";

interface CompareCommandOptions {
  timeout: string;
  runs: string;
  json?: boolean;
}

export interface CompareTargetSummary {
  label: string;
  target: string;
  statusCode?: number;
  averageMs?: number;
  p95Ms?: number;
  tlsVersion: string;
  tlsAuthorized?: boolean;
  redirects?: number;
  server: string;
  contentType: string;
  hstsEnabled: boolean;
  securityHeaders: Record<string, string>;
}

export interface CompareReport {
  left: CompareTargetSummary;
  right: CompareTargetSummary;
  differences: string[];
}

// Registers the compare command and connects two URLs to full doctor diagnostics.
export function registerCompareCommand(program: Command): void {
  program
    .command("compare <leftUrl> <rightUrl>")
    .description("Compare two HTTP targets across status, latency, TLS, redirects, and headers")
    .option("--timeout <ms>", "Per-step timeout in milliseconds", "5000")
    .option("--runs <count>", "Number of HTTP samples for latency comparison", "3")
    .option("--json", "Print the structured comparison report")
    .action(
      async (
        leftUrl: string,
        rightUrl: string,
        options: CompareCommandOptions,
      ) => {
        const timeoutMs = parsePositiveInteger(options.timeout, "timeout");
        const runs = parsePositiveInteger(options.runs, "runs");

        if (timeoutMs === null || runs === null) {
          process.exitCode = 2;
          return;
        }

        try {
          const [leftReport, rightReport] = await Promise.all([
            runDoctor(leftUrl, { timeoutMs, runs }),
            runDoctor(rightUrl, { timeoutMs, runs }),
          ]);
          const report = buildCompareReport(leftReport, rightReport);

          console.log(
            options.json === true
              ? JSON.stringify(report, null, 2)
              : renderCompareReport(report),
          );

          if (!leftReport.result.ok || !rightReport.result.ok) {
            process.exitCode = 1;
          }
        } catch (error) {
          renderCompareError(error);
          process.exitCode = error instanceof InvalidUrlError ? 2 : 3;
        }
      },
    );
}

// Builds the normalized comparison report from two doctor reports.
export function buildCompareReport(
  leftReport: DoctorReport,
  rightReport: DoctorReport,
): CompareReport {
  const left = buildTargetSummary("Left", leftReport);
  const right = buildTargetSummary("Right", rightReport);

  return {
    left,
    right,
    differences: buildDifferences(left, right),
  };
}

// Renders a comparison report in a concise human-readable format.
export function renderCompareReport(report: CompareReport): string {
  return [
    renderSummaryLine(report.left),
    renderSummaryLine(report.right),
    "",
    "Differences:",
    ...renderDifferences(report.differences),
  ].join("\n");
}

// Builds a compact summary for one compared target.
function buildTargetSummary(
  label: string,
  report: DoctorReport,
): CompareTargetSummary {
  const http = report.result.probes.http;
  const tls = report.result.probes.tls;
  const headers = http?.status === "ok" ? http.data.headers : {};
  const summary: CompareTargetSummary = {
    label,
    target: report.result.target.href ?? report.result.target.input,
    tlsVersion: getTlsVersion(tls),
    server: getHeader(headers, "server"),
    contentType: getHeader(headers, "content-type"),
    hstsEnabled: getHeader(headers, "strict-transport-security") !== "missing",
    securityHeaders: getSecurityHeaderStatuses(report),
  };
  const statusCode = getStatusCode(http);
  const tlsAuthorized = getTlsAuthorized(tls);
  const redirects = getRedirectCount(http);

  if (statusCode !== undefined) {
    summary.statusCode = statusCode;
  }

  if (report.result.latency?.averageMs !== undefined) {
    summary.averageMs = report.result.latency.averageMs;
  }

  if (report.result.latency?.p95Ms !== undefined) {
    summary.p95Ms = report.result.latency.p95Ms;
  }

  if (tlsAuthorized !== undefined) {
    summary.tlsAuthorized = tlsAuthorized;
  }

  if (redirects !== undefined) {
    summary.redirects = redirects;
  }

  return summary;
}

// Builds a prioritized list of differences between two target summaries.
function buildDifferences(
  left: CompareTargetSummary,
  right: CompareTargetSummary,
): string[] {
  return [
    ...compareStatusCode(left, right),
    ...compareLatency(left, right),
    ...compareTls(left, right),
    ...compareRedirects(left, right),
    ...compareHeader("Server header", left.server, right.server),
    ...compareHeader("Content-Type", left.contentType, right.contentType),
    ...compareHsts(left, right),
    ...compareSecurityHeaders(left, right),
  ];
}

// Compares HTTP status codes.
function compareStatusCode(
  left: CompareTargetSummary,
  right: CompareTargetSummary,
): string[] {
  if (left.statusCode === right.statusCode) {
    return [];
  }

  return [
    `${right.label} returns ${formatValue(right.statusCode)} while ${left.label} returns ${formatValue(left.statusCode)}.`,
  ];
}

// Compares p95 latency and reports the slower target.
function compareLatency(
  left: CompareTargetSummary,
  right: CompareTargetSummary,
): string[] {
  if (left.p95Ms === undefined || right.p95Ms === undefined) {
    return [];
  }

  const delta = Math.abs(right.p95Ms - left.p95Ms);

  if (delta < 50) {
    return [];
  }

  const slower = right.p95Ms > left.p95Ms ? right : left;

  return [`${slower.label} is slower by ${delta}ms p95.`];
}

// Compares TLS version and authorization state.
function compareTls(
  left: CompareTargetSummary,
  right: CompareTargetSummary,
): string[] {
  const differences: string[] = [];

  if (left.tlsVersion !== right.tlsVersion) {
    differences.push(
      `TLS differs: ${left.label} uses ${left.tlsVersion}, ${right.label} uses ${right.tlsVersion}.`,
    );
  }

  if (left.tlsAuthorized !== right.tlsAuthorized) {
    differences.push("TLS authorization differs.");
  }

  return differences;
}

// Compares redirect counts.
function compareRedirects(
  left: CompareTargetSummary,
  right: CompareTargetSummary,
): string[] {
  if (left.redirects === right.redirects) {
    return [];
  }

  return [
    `Redirects differ: ${left.label} has ${formatValue(left.redirects)}, ${right.label} has ${formatValue(right.redirects)}.`,
  ];
}

// Compares a named header value.
function compareHeader(name: string, left: string, right: string): string[] {
  if (left === right) {
    return [];
  }

  return [`${name} differs: ${left} vs ${right}.`];
}

// Compares HSTS availability.
function compareHsts(
  left: CompareTargetSummary,
  right: CompareTargetSummary,
): string[] {
  if (left.hstsEnabled === right.hstsEnabled) {
    return [];
  }

  return [
    `HSTS differs: ${left.label} is ${formatEnabled(left.hstsEnabled)}, ${right.label} is ${formatEnabled(right.hstsEnabled)}.`,
  ];
}

// Compares browser security header statuses.
function compareSecurityHeaders(
  left: CompareTargetSummary,
  right: CompareTargetSummary,
): string[] {
  const keys = new Set([
    ...Object.keys(left.securityHeaders),
    ...Object.keys(right.securityHeaders),
  ]);
  const differences = [...keys].filter(
    (key) => left.securityHeaders[key] !== right.securityHeaders[key],
  );

  return differences.length > 0 ? ["Security headers differ."] : [];
}

// Renders one target summary line.
function renderSummaryLine(summary: CompareTargetSummary): string {
  return `${summary.label}: ${formatValue(summary.statusCode)} - p95 ${formatDuration(summary.p95Ms)} - HSTS ${formatEnabled(summary.hstsEnabled)} - TLS ${summary.tlsVersion}`;
}

// Renders differences or a no-differences marker.
function renderDifferences(differences: string[]): string[] {
  if (differences.length === 0) {
    return ["- No meaningful differences detected."];
  }

  return differences.map((difference) => `- ${difference}`);
}

// Reads an HTTP status code from a probe result.
function getStatusCode(
  http: ProbeResult<HttpProbeData> | undefined,
): number | undefined {
  return http?.status === "ok" ? http.data.statusCode : undefined;
}

// Reads redirect count from a probe result.
function getRedirectCount(
  http: ProbeResult<HttpProbeData> | undefined,
): number | undefined {
  return http?.status === "ok" ? http.data.redirects.length : undefined;
}

// Reads TLS version from a probe result.
function getTlsVersion(tls: ProbeResult<TlsProbeData> | undefined): string {
  if (tls === undefined) {
    return "not required";
  }

  if (tls.status === "error") {
    return "error";
  }

  return tls.data.protocol ?? "unknown";
}

// Reads TLS authorization state from a probe result.
function getTlsAuthorized(
  tls: ProbeResult<TlsProbeData> | undefined,
): boolean | undefined {
  return tls?.status === "ok" ? tls.data.authorized : undefined;
}

// Reads a response header as a printable lowercase-insensitive value.
function getHeader(
  headers: Record<string, string | string[]>,
  name: string,
): string {
  const value = headers[name.toLowerCase()];

  if (Array.isArray(value)) {
    return value.join(", ");
  }

  return value ?? "missing";
}

// Reads security header statuses from analyzer output.
function getSecurityHeaderStatuses(report: DoctorReport): Record<string, string> {
  const statuses: Record<string, string> = {};

  for (const check of report.securityHeaderAnalysis?.checks ?? []) {
    statuses[check.name] = check.status;
  }

  return statuses;
}

// Formats optional values for terminal output.
function formatValue(value: string | number | undefined): string {
  return value !== undefined ? String(value) : "unknown";
}

// Formats optional millisecond durations.
function formatDuration(value: number | undefined): string {
  return value !== undefined ? `${value}ms` : "unknown";
}

// Formats boolean availability as enabled or missing.
function formatEnabled(value: boolean): string {
  return value ? "enabled" : "missing";
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

// Prints compare command failures that happen before a report is produced.
function renderCompareError(error: unknown): void {
  if (error instanceof Error) {
    console.error(`Compare error: ${error.message}`);
    return;
  }

  console.error("Compare error: Unexpected failure.");
}
