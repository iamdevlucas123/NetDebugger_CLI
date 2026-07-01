import type { ProbeResult } from "./result.js";

export type Severity = "info" | "warning" | "critical";

export type OutputFormat = "console" | "json";

export type DiagnosticCommand =
  | "doctor"
  | "dns"
  | "tcp"
  | "tls"
  | "http"
  | "trace";

export type { ProbeResult } from "./result.js";

export interface SerializableError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface Finding {
  severity: Severity;
  code: string;
  message: string;
  recommendation?: string;
  source?: DiagnosticCommand | "analyzer";
}

export interface SharedCommandOptions {
  outputFormat: OutputFormat;
  timeoutMs: number;
  retries: number;
  verbose: boolean;
}

export interface DoctorCommandOptions extends SharedCommandOptions {
  samples: number;
  followRedirects: boolean;
}

export interface NormalizedTarget {
  input: string;
  protocol?: "http:" | "https:";
  hostname: string;
  port: number;
  path?: string;
  href?: string;
  expectsTls: boolean;
}

export interface DnsProbeData {
  hostname: string;
  ipv4: string[];
  ipv6: string[];
  addresses: string[];
}

export interface TcpProbeData {
  hostname: string;
  port: number;
  connected: boolean;
  remoteAddress?: string;
  remoteFamily?: string;
}

export interface TlsCertificateInfo {
  subject?: string;
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  fingerprint?: string;
  subjectAltNames?: string[];
}

export interface TlsProbeData {
  hostname: string;
  port: number;
  authorized: boolean;
  authorizationError?: string;
  protocol?: string;
  cipher?: string;
  certificate?: TlsCertificateInfo;
}

export interface HttpTiming {
  startAt: string;
  dnsLookupMs?: number;
  tcpConnectionMs?: number;
  tlsHandshakeMs?: number;
  timeToFirstByteMs?: number;
  totalMs: number;
}

export interface HttpRedirect {
  statusCode: number;
  location: string;
}

export interface HttpProbeData {
  url: string;
  finalUrl: string;
  method: "GET" | "HEAD";
  statusCode: number;
  statusText?: string;
  headers: Record<string, string | string[]>;
  redirects: HttpRedirect[];
  timing: HttpTiming;
}

export interface LatencyStats {
  samples: number;
  minMs: number;
  maxMs: number;
  averageMs: number;
  p50Ms: number;
  p95Ms: number;
}

export interface DiagnosticResult {
  command: DiagnosticCommand;
  target: NormalizedTarget;
  ok: boolean;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  probes: {
    dns?: ProbeResult<DnsProbeData>;
    tcp?: ProbeResult<TcpProbeData>;
    tls?: ProbeResult<TlsProbeData>;
    http?: ProbeResult<HttpProbeData>;
  };
  latency?: LatencyStats;
  findings: Finding[];
}
