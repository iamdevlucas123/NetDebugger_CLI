import type { HeaderAnalysis } from "./header.analyzer.js";
import type { LatencyAnalysis } from "./latency.analyzer.js";
import type { SecurityHeaderAnalysis } from "./security-header.analyzer.js";
import type {
  DnsProbeData,
  Finding,
  HttpProbeData,
  ProbeResult,
  TcpProbeData,
  TlsProbeData,
} from "../core/types.js";

export type DiagnosisStatus = "ok" | "warn" | "error";

export interface DiagnosisAnalysis {
  status: DiagnosisStatus;
  score: number;
  mainIssue: string;
  findings: Finding[];
}

export interface DiagnosisInput {
  dns: ProbeResult<DnsProbeData>;
  tcp: ProbeResult<TcpProbeData>;
  tls?: ProbeResult<TlsProbeData>;
  http?: ProbeResult<HttpProbeData>;
  headerAnalysis?: HeaderAnalysis;
  securityHeaderAnalysis?: SecurityHeaderAnalysis;
  latencyAnalysis?: LatencyAnalysis;
}

interface DiagnosisRuleResult {
  penalty: number;
  finding: Finding;
}

// Interprets probe and analyzer results into health score and likely causes.
export function analyzeDiagnosis(input: DiagnosisInput): DiagnosisAnalysis {
  const ruleResults = evaluateDiagnosisRules(input);
  const findings = ruleResults.map((result) => result.finding);
  const score = calculateHealthScore(ruleResults);

  return {
    status: getDiagnosisStatus(score, findings),
    score,
    mainIssue: getMainIssue(findings),
    findings:
      findings.length > 0
        ? findings
        : [
            {
              severity: "info",
              code: "DIAGNOSIS_HEALTHY",
              message: "No major connectivity or application issue was detected.",
              source: "doctor",
            },
          ],
  };
}

// Applies all diagnosis rules in priority order.
function evaluateDiagnosisRules(input: DiagnosisInput): DiagnosisRuleResult[] {
  return [
    ...evaluateDnsRule(input),
    ...evaluateTcpRule(input),
    ...evaluateTlsRule(input),
    ...evaluateHttpRule(input),
    ...evaluateSecurityHeaderRules(input),
    ...evaluateLatencyRule(input),
  ];
}

// Interprets DNS failures as name resolution problems.
function evaluateDnsRule(input: DiagnosisInput): DiagnosisRuleResult[] {
  if (input.dns.status !== "error") {
    return [];
  }

  return [
    {
      penalty: 40,
      finding: {
        severity: "critical",
        code: "DIAGNOSIS_DNS_FAILURE",
        message: "The domain could not be resolved.",
        recommendation: "Check DNS records, the domain name, and authoritative nameservers.",
        source: "doctor",
      },
    },
  ];
}

// Interprets TCP failures as closed ports, firewall blocks, or offline services.
function evaluateTcpRule(input: DiagnosisInput): DiagnosisRuleResult[] {
  if (input.tcp.status !== "error") {
    return [];
  }

  return [
    {
      penalty: 35,
      finding: {
        severity: "critical",
        code: "DIAGNOSIS_TCP_FAILURE",
        message: "The TCP connection failed.",
        recommendation: "Check whether the port is open, blocked by a firewall, or the service is offline.",
        source: "doctor",
      },
    },
  ];
}

// Interprets TLS failures or authorization problems as certificate issues.
function evaluateTlsRule(input: DiagnosisInput): DiagnosisRuleResult[] {
  if (input.tls === undefined) {
    return [];
  }

  if (input.tls.status === "error") {
    return [
      {
        penalty: 25,
        finding: {
          severity: "critical",
          code: "DIAGNOSIS_TLS_FAILURE",
          message: "The SSL/TLS handshake failed.",
          recommendation: "Check certificate validity, SNI, supported TLS versions, and cipher compatibility.",
          source: "doctor",
        },
      },
    ];
  }

  if (!input.tls.data.authorized) {
    return [
      {
        penalty: 25,
        finding: {
          severity: "critical",
          code: "DIAGNOSIS_TLS_UNAUTHORIZED",
          message: "The SSL/TLS certificate is not trusted by the runtime.",
          recommendation: "Check certificate expiration, chain, hostname, and issuer trust.",
          source: "doctor",
        },
      },
    ];
  }

  return [];
}

// Interprets HTTP status codes as application or authorization issues.
function evaluateHttpRule(input: DiagnosisInput): DiagnosisRuleResult[] {
  if (input.http?.status !== "ok") {
    return [];
  }

  const statusCode = input.http.data.statusCode;

  if (statusCode >= 500) {
    return [
      {
        penalty: 30,
        finding: {
          severity: "critical",
          code: "DIAGNOSIS_HTTP_5XX",
          message: "The server responded, but the application or backend is failing.",
          recommendation: "Inspect application logs, upstream services, and deployment health.",
          source: "doctor",
        },
      },
    ];
  }

  if (statusCode >= 400) {
    return [
      {
        penalty: 15,
        finding: {
          severity: "warning",
          code: "DIAGNOSIS_HTTP_4XX",
          message: "The application responded, but the route may be incorrect or unauthorized.",
          recommendation: "Check the URL path, authentication, permissions, and request method.",
          source: "doctor",
        },
      },
    ];
  }

  return [];
}

// Interprets missing key browser security headers as health score penalties.
function evaluateSecurityHeaderRules(input: DiagnosisInput): DiagnosisRuleResult[] {
  const findings = [
    ...(input.headerAnalysis?.findings ?? []),
    ...(input.securityHeaderAnalysis?.findings ?? []),
  ];
  const results: DiagnosisRuleResult[] = [];

  if (hasFinding(findings, "SECURITY_HEADER_CONTENT_SECURITY_POLICY")) {
    results.push({
      penalty: 5,
      finding: {
        severity: "warning",
        code: "DIAGNOSIS_CSP_MISSING",
        message: "Content-Security-Policy is missing.",
        recommendation: "Add a CSP policy to reduce browser-side injection risk.",
        source: "doctor",
      },
    });
  }

  if (hasFinding(findings, "SECURITY_HEADER_STRICT_TRANSPORT_SECURITY")) {
    results.push({
      penalty: 5,
      finding: {
        severity: "warning",
        code: "DIAGNOSIS_HSTS_MISSING",
        message: "Strict-Transport-Security is missing.",
        recommendation: "Add HSTS for HTTPS sites so browsers require secure transport.",
        source: "doctor",
      },
    });
  }

  return results;
}

// Interprets high p95 latency as consistent slowness.
function evaluateLatencyRule(input: DiagnosisInput): DiagnosisRuleResult[] {
  const p95 = input.latencyAnalysis?.stats?.p95Ms;

  if (p95 === undefined || p95 < 1000) {
    return [];
  }

  return [
    {
      penalty: 10,
      finding: {
        severity: p95 >= 3000 ? "critical" : "warning",
        code: "DIAGNOSIS_HIGH_P95_LATENCY",
        message: "The server is responding, but with consistent latency.",
        recommendation: "Inspect backend response time, network path, and repeated redirects.",
        source: "doctor",
      },
    },
  ];
}

// Calculates the health score from rule penalties.
function calculateHealthScore(ruleResults: DiagnosisRuleResult[]): number {
  const penalty = ruleResults.reduce((total, result) => total + result.penalty, 0);

  return Math.max(0, 100 - penalty);
}

// Converts score and severity into a top-level diagnosis status.
function getDiagnosisStatus(score: number, findings: Finding[]): DiagnosisStatus {
  if (findings.some((finding) => finding.severity === "critical") || score < 70) {
    return "error";
  }

  if (findings.some((finding) => finding.severity === "warning") || score < 95) {
    return "warn";
  }

  return "ok";
}

// Selects the primary issue to show in reports.
function getMainIssue(findings: Finding[]): string {
  const importantFinding =
    findings.find((finding) => finding.severity === "critical") ??
    findings.find((finding) => finding.severity === "warning");

  return importantFinding?.message ?? "No major issue detected.";
}

// Checks whether analyzer findings contain a stable code.
function hasFinding(findings: Finding[], code: string): boolean {
  return findings.some((finding) => finding.code === code);
}
