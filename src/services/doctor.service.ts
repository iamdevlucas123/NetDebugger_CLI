import {
  analyzeHeaders,
  type HeaderAnalysis,
} from "../analyzers/header.analyzer.js";
import {
  analyzeSecurityHeaders,
  type SecurityHeaderAnalysis,
} from "../analyzers/security-header.analyzer.js";
import {
  analyzeLatency,
  type LatencyAnalysis,
} from "../analyzers/latency.analyzer.js";
import {
  analyzeDiagnosis,
  type DiagnosisAnalysis,
} from "../analyzers/diagnosis.engine.js";
import { InvalidUrlError } from "../core/errors.js";
import type {
  DiagnosticResult,
  DnsProbeData,
  Finding,
  HttpProbeData,
  NormalizedTarget,
  ProbeResult,
  TcpProbeData,
  TlsProbeData,
} from "../core/types.js";
import { resolveDns } from "../probes/dns.probe.js";
import { probeHttp } from "../probes/http.probe.js";
import { connectTcp } from "../probes/tcp.probe.js";
import { probeTls } from "../probes/tls.probe.js";

export interface DoctorServiceOptions {
  timeoutMs?: number;
  runs?: number;
  verbose?: boolean;
}

export interface DoctorReport {
  result: DiagnosticResult;
  httpRuns: Array<ProbeResult<HttpProbeData>>;
  headerAnalysis?: HeaderAnalysis;
  securityHeaderAnalysis?: SecurityHeaderAnalysis;
  latencyAnalysis?: LatencyAnalysis;
  diagnosisAnalysis?: DiagnosisAnalysis;
}

export interface DoctorServiceDependencies {
  resolveDns?: typeof resolveDns;
  connectTcp?: typeof connectTcp;
  probeTls?: typeof probeTls;
  probeHttp?: typeof probeHttp;
  analyzeHeaders?: typeof analyzeHeaders;
  analyzeSecurityHeaders?: typeof analyzeSecurityHeaders;
  analyzeLatency?: typeof analyzeLatency;
  analyzeDiagnosis?: typeof analyzeDiagnosis;
  now?: () => Date;
}

// Runs the full doctor diagnostic workflow and returns a structured report.
export async function runDoctor(
  input: string,
  options: DoctorServiceOptions = {},
  dependencies: DoctorServiceDependencies = {},
): Promise<DoctorReport> {
  const startedAt = getNow(dependencies).getTime();
  const target = parseDoctorTarget(input);
  const timeoutMs = options.timeoutMs ?? 5000;
  const runs = options.runs ?? 1;
  const doctorDependencies = buildDoctorDependencies(dependencies);

  const dns = await doctorDependencies.resolveDns(target.hostname);
  const tcp = await doctorDependencies.connectTcp(target.hostname, target.port, {
    timeoutMs,
  });
  const tls = target.expectsTls
    ? await doctorDependencies.probeTls(target.hostname, target.port, {
        timeoutMs,
      })
    : undefined;
  const httpRuns = await runHttpSamples(
    target,
    runs,
    timeoutMs,
    doctorDependencies.probeHttp,
  );
  const http = getLastItem(httpRuns);
  const headerAnalysis =
    http?.status === "ok"
      ? doctorDependencies.analyzeHeaders(http.data.headers)
      : undefined;
  const securityHeaderAnalysis =
    http?.status === "ok"
      ? doctorDependencies.analyzeSecurityHeaders(http.data.headers)
      : undefined;
  const latencyAnalysis = doctorDependencies.analyzeLatency({
    dns,
    tcp,
    ...(tls !== undefined ? { tls } : {}),
    httpRuns,
  });
  const diagnosisAnalysis = doctorDependencies.analyzeDiagnosis({
    dns,
    tcp,
    ...(tls !== undefined ? { tls } : {}),
    ...(http !== undefined ? { http } : {}),
    ...(headerAnalysis !== undefined ? { headerAnalysis } : {}),
    ...(securityHeaderAnalysis !== undefined ? { securityHeaderAnalysis } : {}),
    latencyAnalysis,
  });
  const completedAt = getNow(dependencies).getTime();
  const findings = buildFindings({
    dns,
    tcp,
    tls,
    http,
    headerAnalysis,
    securityHeaderAnalysis,
    latencyAnalysis,
    diagnosisAnalysis,
  });
  const probes: DiagnosticResult["probes"] = {
    dns,
    tcp,
  };

  if (tls !== undefined) {
    probes.tls = tls;
  }

  if (http !== undefined) {
    probes.http = http;
  }

  const result: DiagnosticResult = {
    command: "doctor",
    target,
    ok: isDoctorHealthy({ dns, tcp, tls, http, findings }),
    startedAt: new Date(startedAt).toISOString(),
    completedAt: new Date(completedAt).toISOString(),
    durationMs: Math.max(0, Math.round(completedAt - startedAt)),
    probes,
    findings,
  };

  if (latencyAnalysis.stats !== undefined) {
    result.latency = latencyAnalysis.stats;
  }

  return buildDoctorReport({
    result,
    httpRuns,
    headerAnalysis,
    securityHeaderAnalysis,
    latencyAnalysis,
    diagnosisAnalysis,
  });
}

// Parses and normalizes a doctor input URL.
function parseDoctorTarget(input: string): NormalizedTarget {
  const normalizedInput = normalizeDoctorInput(input);
  let url: URL;

  try {
    url = new URL(normalizedInput);
  } catch (cause) {
    throw new InvalidUrlError("Invalid URL for doctor command.", {
      target: input,
      cause,
    });
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new InvalidUrlError("Doctor supports only http and https URLs.", {
      target: input,
      details: {
        protocol: url.protocol,
      },
    });
  }

  return {
    input,
    protocol: url.protocol,
    hostname: url.hostname,
    port: getPort(url),
    path: `${url.pathname}${url.search}`,
    href: url.href,
    expectsTls: url.protocol === "https:",
  };
}

// Adds a default HTTPS protocol when the user provides only a hostname.
function normalizeDoctorInput(input: string): string {
  const trimmedInput = input.trim();

  if (/^[a-z][a-z\d+\-.]*:\/\//i.test(trimmedInput)) {
    return trimmedInput;
  }

  return `https://${trimmedInput}`;
}

// Selects the explicit URL port or the protocol default.
function getPort(url: URL): number {
  if (url.port !== "") {
    return Number(url.port);
  }

  return url.protocol === "https:" ? 443 : 80;
}

// Builds the probe and analyzer dependencies used by the workflow.
function buildDoctorDependencies(
  dependencies: DoctorServiceDependencies,
): Required<
  Pick<
    DoctorServiceDependencies,
    | "resolveDns"
    | "connectTcp"
    | "probeTls"
    | "probeHttp"
    | "analyzeHeaders"
    | "analyzeSecurityHeaders"
    | "analyzeLatency"
    | "analyzeDiagnosis"
  >
> {
  return {
    resolveDns: dependencies.resolveDns ?? resolveDns,
    connectTcp: dependencies.connectTcp ?? connectTcp,
    probeTls: dependencies.probeTls ?? probeTls,
    probeHttp: dependencies.probeHttp ?? probeHttp,
    analyzeHeaders: dependencies.analyzeHeaders ?? analyzeHeaders,
    analyzeSecurityHeaders:
      dependencies.analyzeSecurityHeaders ?? analyzeSecurityHeaders,
    analyzeLatency: dependencies.analyzeLatency ?? analyzeLatency,
    analyzeDiagnosis: dependencies.analyzeDiagnosis ?? analyzeDiagnosis,
  };
}

// Runs the configured number of HTTP samples in sequence.
async function runHttpSamples(
  target: NormalizedTarget,
  runs: number,
  timeoutMs: number,
  requestHttp: typeof probeHttp,
): Promise<Array<ProbeResult<HttpProbeData>>> {
  const sampleCount = Math.max(1, Math.round(runs));
  const results: Array<ProbeResult<HttpProbeData>> = [];

  for (let index = 0; index < sampleCount; index++) {
    results.push(
      await requestHttp(target.href ?? target.input, {
        timeoutMs,
      }),
    );
  }

  return results;
}

// Builds probe, analyzer, latency, and diagnosis findings.
function buildFindings(input: {
  dns: ProbeResult<DnsProbeData>;
  tcp: ProbeResult<TcpProbeData>;
  tls: ProbeResult<TlsProbeData> | undefined;
  http: ProbeResult<HttpProbeData> | undefined;
  headerAnalysis: HeaderAnalysis | undefined;
  securityHeaderAnalysis: SecurityHeaderAnalysis | undefined;
  latencyAnalysis: LatencyAnalysis;
  diagnosisAnalysis: DiagnosisAnalysis;
}): Finding[] {
  return [
    ...buildProbeFindings(input.dns, "dns"),
    ...buildProbeFindings(input.tcp, "tcp"),
    ...(input.tls !== undefined ? buildProbeFindings(input.tls, "tls") : []),
    ...(input.http !== undefined ? buildProbeFindings(input.http, "http") : []),
    ...(input.headerAnalysis?.findings ?? []),
    ...(input.securityHeaderAnalysis?.findings ?? []),
    ...input.latencyAnalysis.findings,
    ...input.diagnosisAnalysis.findings,
  ];
}

// Converts a failed probe result into a diagnostic finding.
function buildProbeFindings<TData>(
  result: ProbeResult<TData>,
  source: "dns" | "tcp" | "tls" | "http",
): Finding[] {
  if (result.status === "ok") {
    return [];
  }

  return [
    {
      severity: "critical",
      code: result.error.code,
      message: result.error.message,
      source,
    },
  ];
}

// Determines whether the full doctor result is healthy enough for exit code zero.
function isDoctorHealthy(input: {
  dns: ProbeResult<DnsProbeData>;
  tcp: ProbeResult<TcpProbeData>;
  tls: ProbeResult<TlsProbeData> | undefined;
  http: ProbeResult<HttpProbeData> | undefined;
  findings: Finding[];
}): boolean {
  return (
    input.dns.status === "ok" &&
    input.tcp.status === "ok" &&
    input.tls?.status !== "error" &&
    input.http?.status === "ok" &&
    !input.findings.some((finding) => finding.severity === "critical")
  );
}

// Builds the final report while respecting exact optional property semantics.
function buildDoctorReport(input: {
  result: DiagnosticResult;
  httpRuns: Array<ProbeResult<HttpProbeData>>;
  headerAnalysis: HeaderAnalysis | undefined;
  securityHeaderAnalysis: SecurityHeaderAnalysis | undefined;
  latencyAnalysis: LatencyAnalysis | undefined;
  diagnosisAnalysis: DiagnosisAnalysis | undefined;
}): DoctorReport {
  const report: DoctorReport = {
    result: input.result,
    httpRuns: input.httpRuns,
  };

  if (input.headerAnalysis !== undefined) {
    report.headerAnalysis = input.headerAnalysis;
  }

  if (input.securityHeaderAnalysis !== undefined) {
    report.securityHeaderAnalysis = input.securityHeaderAnalysis;
  }

  if (input.latencyAnalysis !== undefined) {
    report.latencyAnalysis = input.latencyAnalysis;
  }

  if (input.diagnosisAnalysis !== undefined) {
    report.diagnosisAnalysis = input.diagnosisAnalysis;
  }

  return report;
}

// Reads the final item from an array without mutating it.
function getLastItem<TItem>(items: TItem[]): TItem | undefined {
  return items[items.length - 1];
}

// Returns the injected clock or the system clock for timestamps.
function getNow(dependencies: DoctorServiceDependencies): Date {
  return dependencies.now?.() ?? new Date();
}
