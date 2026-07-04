import type {
  DnsProbeData,
  Finding,
  HttpProbeData,
  ProbeResult,
  TcpProbeData,
  TlsProbeData,
} from "../core/types.js";
import type { DoctorReport } from "../services/doctor.service.js";

export type JsonReportStatus = "ok" | "warn" | "error";

export interface DoctorJsonPayload {
  target: string;
  status: JsonReportStatus;
  score: number;
  dns: ProbeResult<DnsProbeData> | null;
  tcp: ProbeResult<TcpProbeData> | null;
  tls: ProbeResult<TlsProbeData> | null;
  http: ProbeResult<HttpProbeData> | null;
  headers: {
    common: DoctorReport["headerAnalysis"] | null;
    security: DoctorReport["securityHeaderAnalysis"] | null;
    latency: DoctorReport["latencyAnalysis"] | null;
  };
  diagnosis: Finding[];
}

// Renders the doctor report as stable JSON for automation.
export function renderDoctorJsonReport(report: DoctorReport): string {
  return JSON.stringify(buildDoctorJsonPayload(report), null, 2);
}

// Builds the serializable doctor JSON payload.
export function buildDoctorJsonPayload(report: DoctorReport): DoctorJsonPayload {
  return {
    target: report.result.target.href ?? report.result.target.input,
    status: getReportStatus(report.result.findings),
    score: calculateScore(report.result.findings),
    dns: report.result.probes.dns ?? null,
    tcp: report.result.probes.tcp ?? null,
    tls: report.result.probes.tls ?? null,
    http: report.result.probes.http ?? null,
    headers: {
      common: report.headerAnalysis ?? null,
      security: report.securityHeaderAnalysis ?? null,
      latency: report.latencyAnalysis ?? null,
    },
    diagnosis: report.result.findings,
  };
}

// Calculates a simple health score from diagnostic findings.
function calculateScore(findings: Finding[]): number {
  const penalty = findings.reduce((total, finding) => {
    if (finding.severity === "critical") {
      return total + 30;
    }

    if (finding.severity === "warning") {
      return total + 10;
    }

    return total;
  }, 0);

  return Math.max(0, 100 - penalty);
}

// Converts diagnostic findings into a top-level JSON status.
function getReportStatus(findings: Finding[]): JsonReportStatus {
  if (findings.some((finding) => finding.severity === "critical")) {
    return "error";
  }

  if (findings.some((finding) => finding.severity === "warning")) {
    return "warn";
  }

  return "ok";
}
