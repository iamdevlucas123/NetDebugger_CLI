import type { Finding } from "../core/types.js";
import type { DoctorReport } from "../services/doctor.service.js";
import { buildDoctorJsonPayload } from "./json.reporter.js";
import { renderDoctorTable } from "./table.reporter.js";

export interface ConsoleReporterOptions {
  verbose?: boolean;
  includeHeaders?: boolean;
}

// Renders the doctor report as human-readable terminal output.
export function renderDoctorConsoleReport(
  report: DoctorReport,
  options: ConsoleReporterOptions = {},
): string {
  return [
    renderSummary(report),
    renderDoctorTable(report),
    renderHeaders(report, Boolean(options.includeHeaders)),
    renderLatency(report),
    renderFindings(report.result.findings, Boolean(options.verbose)),
  ]
    .filter((section) => section.length > 0)
    .join("\n\n");
}

// Renders selected HTTP headers when requested by the user.
function renderHeaders(report: DoctorReport, includeHeaders: boolean): string {
  if (!includeHeaders) {
    return "";
  }

  const http = report.result.probes.http;

  if (http?.status !== "ok") {
    return "Headers: unavailable";
  }

  const headers = http.data.headers;

  return [
    "Headers:",
    `Content-Type: ${formatHeader(headers["content-type"])}`,
    `Cache-Control: ${formatHeader(headers["cache-control"])}`,
    `Server: ${formatHeader(headers.server)}`,
    `Location: ${formatHeader(headers.location)}`,
  ].join("\n");
}

// Renders the top-level doctor status summary.
function renderSummary(report: DoctorReport): string {
  const payload = buildDoctorJsonPayload(report);

  return [
    `Target: ${payload.target}`,
    `Status: ${payload.status.toUpperCase()}`,
    `Health Score: ${payload.score}/100`,
    `Main issue: ${payload.mainIssue}`,
    `Runs: ${report.httpRuns.length}`,
    `Total time: ${report.result.durationMs}ms`,
  ].join("\n");
}

// Renders latency phases and sample statistics.
function renderLatency(report: DoctorReport): string {
  const phases = report.latencyAnalysis?.phases;
  const stats = report.result.latency;

  if (phases === undefined && stats === undefined) {
    return "";
  }

  const lines = ["Latency:"];

  if (phases !== undefined) {
    lines.push(`DNS: ${formatOptionalDuration(phases.dnsLookupMs)}`);
    lines.push(`TCP: ${formatOptionalDuration(phases.tcpConnectMs)}`);
    lines.push(`TLS: ${formatOptionalDuration(phases.tlsHandshakeMs)}`);
    lines.push(`TTFB: ${formatOptionalDuration(phases.ttfbMs)}`);
    lines.push(`HTTP total: ${formatOptionalDuration(phases.httpTotalMs)}`);
  }

  if (stats !== undefined) {
    lines.push(
      `Samples: min ${stats.minMs}ms, max ${stats.maxMs}ms, avg ${stats.averageMs}ms, p50 ${stats.p50Ms}ms, p95 ${stats.p95Ms}ms`,
    );
  }

  return lines.join("\n");
}

// Renders diagnostic findings for console output.
function renderFindings(findings: Finding[], verbose: boolean): string {
  const visibleFindings = verbose
    ? findings
    : findings.filter((finding) => finding.severity !== "info");

  if (visibleFindings.length === 0) {
    return "Findings: none";
  }

  return [
    `Findings: ${visibleFindings.length}`,
    ...visibleFindings.flatMap((finding) => formatFinding(finding)),
  ].join("\n");
}

// Formats one finding with its recommendation when available.
function formatFinding(finding: Finding): string[] {
  const lines = [
    `- [${finding.severity}] ${finding.code}: ${finding.message}`,
  ];

  if (finding.recommendation !== undefined) {
    lines.push(`  Possible action: ${finding.recommendation}`);
  }

  return lines;
}

// Formats a header value for console output.
function formatHeader(value: string | string[] | undefined): string {
  if (Array.isArray(value)) {
    return value.join(", ");
  }

  return value ?? "missing";
}

// Formats optional millisecond durations for console output.
function formatOptionalDuration(value: number | undefined): string {
  return value !== undefined ? `${value}ms` : "none";
}
