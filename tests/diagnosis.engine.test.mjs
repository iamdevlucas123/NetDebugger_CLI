import assert from "node:assert/strict";
import test from "node:test";

import { analyzeDiagnosis } from "../dist/analyzers/diagnosis.engine.js";
import { createErrorResult, createOkResult } from "../dist/core/result.js";

// Creates a successful DNS result for diagnosis tests.
function dnsOk() {
  return createOkResult({
    target: "example.com",
    durationMs: 10,
    data: {
      hostname: "example.com",
      ipv4: ["93.184.216.34"],
      ipv6: [],
      addresses: ["93.184.216.34"],
    },
  });
}

// Creates a failed DNS result for diagnosis tests.
function dnsError() {
  return createErrorResult({
    target: "example.com",
    durationMs: 10,
    error: {
      code: "DNS_ERROR",
      message: "DNS failed.",
    },
  });
}

// Creates a successful TCP result for diagnosis tests.
function tcpOk() {
  return createOkResult({
    target: "example.com:443",
    durationMs: 20,
    data: {
      hostname: "example.com",
      port: 443,
      connected: true,
    },
  });
}

// Creates a failed TCP result for diagnosis tests.
function tcpError() {
  return createErrorResult({
    target: "example.com:443",
    durationMs: 20,
    error: {
      code: "TCP_CONNECTION_ERROR",
      message: "TCP failed.",
    },
  });
}

// Creates a successful TLS result for diagnosis tests.
function tlsOk() {
  return createOkResult({
    target: "example.com:443",
    durationMs: 30,
    data: {
      hostname: "example.com",
      port: 443,
      authorized: true,
    },
  });
}

// Creates a failed TLS result for diagnosis tests.
function tlsError() {
  return createErrorResult({
    target: "example.com:443",
    durationMs: 30,
    error: {
      code: "TLS_HANDSHAKE_ERROR",
      message: "TLS failed.",
    },
  });
}

// Creates a successful HTTP result with a configurable status code.
function httpOk(statusCode) {
  return createOkResult({
    target: "https://example.com",
    durationMs: 40,
    data: {
      url: "https://example.com",
      finalUrl: "https://example.com",
      method: "GET",
      statusCode,
      headers: {},
      redirects: [],
      timing: {
        startAt: "2026-07-03T00:00:00.000Z",
        totalMs: 40,
      },
    },
  });
}

test("analyzeDiagnosis explains DNS failures and applies score penalty", () => {
  const analysis = analyzeDiagnosis({
    dns: dnsError(),
    tcp: tcpOk(),
    tls: tlsOk(),
    http: httpOk(200),
  });

  assert.equal(analysis.status, "error");
  assert.equal(analysis.score, 60);
  assert.equal(analysis.mainIssue, "The domain could not be resolved.");
  assert.equal(analysis.findings[0].code, "DIAGNOSIS_DNS_FAILURE");
});

test("analyzeDiagnosis explains TCP and TLS failures", () => {
  const tcpAnalysis = analyzeDiagnosis({
    dns: dnsOk(),
    tcp: tcpError(),
    tls: tlsOk(),
    http: httpOk(200),
  });
  const tlsAnalysis = analyzeDiagnosis({
    dns: dnsOk(),
    tcp: tcpOk(),
    tls: tlsError(),
    http: httpOk(200),
  });

  assert.equal(tcpAnalysis.score, 65);
  assert.equal(tcpAnalysis.findings[0].code, "DIAGNOSIS_TCP_FAILURE");
  assert.equal(tlsAnalysis.score, 75);
  assert.equal(tlsAnalysis.findings[0].code, "DIAGNOSIS_TLS_FAILURE");
});

test("analyzeDiagnosis distinguishes HTTP 5xx and 4xx responses", () => {
  const serverError = analyzeDiagnosis({
    dns: dnsOk(),
    tcp: tcpOk(),
    tls: tlsOk(),
    http: httpOk(503),
  });
  const clientError = analyzeDiagnosis({
    dns: dnsOk(),
    tcp: tcpOk(),
    tls: tlsOk(),
    http: httpOk(404),
  });

  assert.equal(serverError.status, "error");
  assert.equal(serverError.score, 70);
  assert.equal(serverError.findings[0].code, "DIAGNOSIS_HTTP_5XX");
  assert.equal(clientError.status, "warn");
  assert.equal(clientError.score, 85);
  assert.equal(clientError.findings[0].code, "DIAGNOSIS_HTTP_4XX");
});

test("analyzeDiagnosis penalizes missing security headers and high p95 latency", () => {
  const analysis = analyzeDiagnosis({
    dns: dnsOk(),
    tcp: tcpOk(),
    tls: tlsOk(),
    http: httpOk(200),
    securityHeaderAnalysis: {
      checks: [],
      findings: [
        {
          severity: "critical",
          code: "SECURITY_HEADER_CONTENT_SECURITY_POLICY",
          message: "CSP header is missing.",
          source: "analyzer",
        },
        {
          severity: "critical",
          code: "SECURITY_HEADER_STRICT_TRANSPORT_SECURITY",
          message: "HSTS header is missing.",
          source: "analyzer",
        },
      ],
    },
    latencyAnalysis: {
      phases: {},
      stats: {
        samples: 3,
        minMs: 900,
        maxMs: 1400,
        averageMs: 1100,
        p50Ms: 1000,
        p95Ms: 1400,
      },
      findings: [],
    },
  });

  assert.equal(analysis.status, "warn");
  assert.equal(analysis.score, 80);
  assert.deepEqual(
    analysis.findings.map((finding) => finding.code),
    [
      "DIAGNOSIS_CSP_MISSING",
      "DIAGNOSIS_HSTS_MISSING",
      "DIAGNOSIS_HIGH_P95_LATENCY",
    ],
  );
});
