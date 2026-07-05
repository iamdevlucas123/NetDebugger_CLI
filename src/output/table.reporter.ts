import Table from "cli-table3";

import type { Finding, HttpProbeData, ProbeResult } from "../core/types.js";
import type { DoctorReport } from "../services/doctor.service.js";

type RowStatus = "OK" | "WARN" | "ERROR" | "SKIP";

// Renders the doctor report as a terminal table.
export function renderDoctorTable(report: DoctorReport): string {
  const table = new Table({
    head: ["Test", "Status", "Result", "Time"],
    colWidths: [12, 10, 32, 10],
    wordWrap: true,
  });

  table.push(
    buildDnsRow(report),
    buildTcpRow(report),
    buildTlsRow(report),
    buildHttpRow(report),
    buildHeadersRow(report),
  );

  return table.toString();
}

// Builds the DNS row from the DNS probe result.
function buildDnsRow(report: DoctorReport): string[] {
  const dns = report.result.probes.dns;

  if (dns === undefined) {
    return ["DNS", "SKIP", "not executed", "-"];
  }

  if (dns.status === "error") {
    return ["DNS", "ERROR", dns.error.message, formatDuration(dns.durationMs)];
  }

  return [
    "DNS",
    "OK",
    formatDnsResult(dns),
    formatDuration(dns.durationMs),
  ];
}

// Formats DNS rows with resolver source context.
function formatDnsResult(
  dns: Extract<DoctorReport["result"]["probes"]["dns"], { status: "ok" }>,
): string {
  const suffix =
    dns.data.resolver === "system-fallback" ? " via system resolver" : "";

  return `${dns.data.addresses.length} records${suffix}`;
}

// Builds the TCP row from the TCP probe result.
function buildTcpRow(report: DoctorReport): string[] {
  const tcp = report.result.probes.tcp;

  if (tcp === undefined) {
    return ["TCP", "SKIP", "not executed", "-"];
  }

  if (tcp.status === "error") {
    return ["TCP", "ERROR", tcp.error.message, formatDuration(tcp.durationMs)];
  }

  return ["TCP", "OK", "port open", formatDuration(tcp.durationMs)];
}

// Builds the TLS row from the TLS probe result.
function buildTlsRow(report: DoctorReport): string[] {
  const tls = report.result.probes.tls;

  if (!report.result.target.expectsTls) {
    return ["TLS", "SKIP", "not required", "-"];
  }

  if (tls === undefined) {
    return ["TLS", "SKIP", "not executed", "-"];
  }

  if (tls.status === "error") {
    return ["TLS", "ERROR", tls.error.message, formatDuration(tls.durationMs)];
  }

  return [
    "TLS",
    "OK",
    tls.data.protocol ?? "handshake ok",
    formatDuration(tls.durationMs),
  ];
}

// Builds the HTTP row from the HTTP probe result.
function buildHttpRow(report: DoctorReport): string[] {
  const http = report.result.probes.http;

  if (http === undefined) {
    return ["HTTP", "SKIP", "not executed", "-"];
  }

  if (http.status === "error") {
    return ["HTTP", "ERROR", http.error.message, formatDuration(http.durationMs)];
  }

  return ["HTTP", getHttpStatus(http), formatHttpResult(http), formatDuration(http.durationMs)];
}

// Builds the headers row from analyzer findings.
function buildHeadersRow(report: DoctorReport): string[] {
  const findings = [
    ...(report.headerAnalysis?.findings ?? []),
    ...(report.securityHeaderAnalysis?.findings ?? []),
  ];
  const status = getHeaderFindingsStatus(findings);
  const result = getHeadersResult(findings);

  return ["Headers", status, result, "-"];
}

// Converts HTTP status codes into table status values.
function getHttpStatus(result: ProbeResult<HttpProbeData>): RowStatus {
  if (result.status === "error") {
    return "ERROR";
  }

  return result.data.statusCode >= 500 ? "WARN" : "OK";
}

// Formats the HTTP status code and text for display.
function formatHttpResult(result: ProbeResult<HttpProbeData>): string {
  if (result.status === "error") {
    return result.error.message;
  }

  return `${result.data.statusCode} ${result.data.statusText ?? ""}`.trimEnd();
}

// Classifies header findings as warnings because they do not block connectivity.
function getHeaderFindingsStatus(findings: Finding[]): RowStatus {
  if (findings.length > 0) {
    return "WARN";
  }

  return "OK";
}

// Selects the most important header finding for the table result.
function getHeadersResult(findings: Finding[]): string {
  const importantFinding =
    findings.find((finding) => finding.severity === "critical") ??
    findings.find((finding) => finding.severity === "warning") ??
    findings[0];

  return importantFinding?.message ?? "headers ok";
}

// Formats millisecond durations for table cells.
function formatDuration(value: number): string {
  return `${value}ms`;
}
