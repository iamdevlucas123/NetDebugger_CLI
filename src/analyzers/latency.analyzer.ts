import type {
  DnsProbeData,
  Finding,
  HttpProbeData,
  LatencyStats,
  ProbeResult,
  TcpProbeData,
  TlsProbeData,
} from "../core/types.js";

export interface LatencyPhaseTimings {
  dnsLookupMs?: number;
  tcpConnectMs?: number;
  tlsHandshakeMs?: number;
  ttfbMs?: number;
  httpTotalMs?: number;
}

export interface LatencyAnalysis {
  phases: LatencyPhaseTimings;
  stats?: LatencyStats;
  findings: Finding[];
}

export interface LatencyAnalyzerInput {
  dns: ProbeResult<DnsProbeData>;
  tcp: ProbeResult<TcpProbeData>;
  tls?: ProbeResult<TlsProbeData>;
  httpRuns: Array<ProbeResult<HttpProbeData>>;
}

// Analyzes probe durations and repeated HTTP samples into latency metrics.
export function analyzeLatency(input: LatencyAnalyzerInput): LatencyAnalysis {
  const phases = buildPhaseTimings(input);
  const stats = calculateLatencyStats(getSuccessfulHttpDurations(input.httpRuns));
  const findings = buildLatencyFindings(stats, phases);
  const analysis: LatencyAnalysis = {
    phases,
    findings,
  };

  if (stats !== undefined) {
    analysis.stats = stats;
  }

  return analysis;
}

// Builds one-pass phase timings from the latest probe results.
function buildPhaseTimings(input: LatencyAnalyzerInput): LatencyPhaseTimings {
  const latestHttp = getLastItem(input.httpRuns);
  const phases: LatencyPhaseTimings = {};

  if (input.dns.status === "ok") {
    phases.dnsLookupMs = input.dns.durationMs;
  }

  if (input.tcp.status === "ok") {
    phases.tcpConnectMs = input.tcp.durationMs;
  }

  if (input.tls?.status === "ok") {
    phases.tlsHandshakeMs = input.tls.durationMs;
  }

  if (latestHttp?.status === "ok") {
    phases.httpTotalMs = latestHttp.durationMs;

    if (latestHttp.data.timing.timeToFirstByteMs !== undefined) {
      phases.ttfbMs = latestHttp.data.timing.timeToFirstByteMs;
    }
  }

  return phases;
}

// Extracts durations from successful HTTP samples.
function getSuccessfulHttpDurations(
  httpRuns: Array<ProbeResult<HttpProbeData>>,
): number[] {
  return httpRuns
    .filter((result): result is ProbeResult<HttpProbeData> & { status: "ok" } => result.status === "ok")
    .map((result) => result.durationMs);
}

// Calculates min, max, average, p50, and p95 from HTTP sample durations.
function calculateLatencyStats(durations: number[]): LatencyStats | undefined {
  if (durations.length === 0) {
    return undefined;
  }

  const sortedDurations = [...durations].sort((left, right) => left - right);
  const total = sortedDurations.reduce((sum, value) => sum + value, 0);

  return {
    samples: sortedDurations.length,
    minMs: sortedDurations[0] ?? 0,
    maxMs: sortedDurations[sortedDurations.length - 1] ?? 0,
    averageMs: Math.round(total / sortedDurations.length),
    p50Ms: percentile(sortedDurations, 50),
    p95Ms: percentile(sortedDurations, 95),
  };
}

// Reads a nearest-rank percentile from sorted latency values.
function percentile(sortedValues: number[], percentileValue: number): number {
  const index = Math.max(
    0,
    Math.ceil((percentileValue / 100) * sortedValues.length) - 1,
  );

  return sortedValues[index] ?? 0;
}

// Emits findings when measured latency crosses practical thresholds.
function buildLatencyFindings(
  stats: LatencyStats | undefined,
  phases: LatencyPhaseTimings,
): Finding[] {
  const findings: Finding[] = [];

  if (stats !== undefined && stats.p95Ms >= 1000) {
    findings.push({
      severity: stats.p95Ms >= 3000 ? "critical" : "warning",
      code: "HIGH_HTTP_LATENCY",
      message: `HTTP p95 latency is ${stats.p95Ms}ms.`,
      recommendation: "Inspect server response time, network path, and redirects.",
      source: "analyzer",
    });
  }

  if (phases.dnsLookupMs !== undefined && phases.dnsLookupMs >= 500) {
    findings.push({
      severity: "warning",
      code: "HIGH_DNS_LATENCY",
      message: `DNS lookup took ${phases.dnsLookupMs}ms.`,
      recommendation: "Check recursive resolver performance and DNS provider health.",
      source: "analyzer",
    });
  }

  if (phases.tcpConnectMs !== undefined && phases.tcpConnectMs >= 1000) {
    findings.push({
      severity: "warning",
      code: "HIGH_TCP_LATENCY",
      message: `TCP connect took ${phases.tcpConnectMs}ms.`,
      recommendation: "Inspect network path, firewall latency, and target load balancers.",
      source: "analyzer",
    });
  }

  if (phases.tlsHandshakeMs !== undefined && phases.tlsHandshakeMs >= 1000) {
    findings.push({
      severity: "warning",
      code: "HIGH_TLS_LATENCY",
      message: `TLS handshake took ${phases.tlsHandshakeMs}ms.`,
      recommendation: "Check TLS configuration, certificate chain size, and network latency.",
      source: "analyzer",
    });
  }

  return findings;
}

// Reads the final item from an array without mutating it.
function getLastItem<TItem>(items: TItem[]): TItem | undefined {
  return items[items.length - 1];
}
