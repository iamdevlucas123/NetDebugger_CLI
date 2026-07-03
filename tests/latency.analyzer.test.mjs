import assert from "node:assert/strict";
import test from "node:test";

import { analyzeLatency } from "../dist/analyzers/latency.analyzer.js";
import { createOkResult } from "../dist/core/result.js";

// Creates a successful probe result with arbitrary serializable data.
function okResult(target, durationMs, data) {
  return createOkResult({
    target,
    durationMs,
    data,
  });
}

// Creates a successful HTTP probe result with configurable duration and TTFB.
function httpOk(url, durationMs, timeToFirstByteMs) {
  return okResult(url, durationMs, {
    url,
    finalUrl: url,
    method: "GET",
    statusCode: 200,
    headers: {},
    redirects: [],
    timing: {
      startAt: "2026-07-03T00:00:00.000Z",
      totalMs: durationMs,
      timeToFirstByteMs,
    },
  });
}

test("analyzeLatency reports phase timings and HTTP sample statistics", () => {
  const analysis = analyzeLatency({
    dns: okResult("example.com", 12, {
      hostname: "example.com",
      ipv4: ["93.184.216.34"],
      ipv6: [],
      addresses: ["93.184.216.34"],
    }),
    tcp: okResult("example.com:443", 34, {
      hostname: "example.com",
      port: 443,
      connected: true,
    }),
    tls: okResult("example.com:443", 56, {
      hostname: "example.com",
      port: 443,
      authorized: true,
    }),
    httpRuns: [
      httpOk("https://example.com", 100, 40),
      httpOk("https://example.com", 200, 80),
      httpOk("https://example.com", 300, 120),
      httpOk("https://example.com", 400, 160),
    ],
  });

  assert.deepEqual(analysis.phases, {
    dnsLookupMs: 12,
    tcpConnectMs: 34,
    tlsHandshakeMs: 56,
    ttfbMs: 160,
    httpTotalMs: 400,
  });
  assert.deepEqual(analysis.stats, {
    samples: 4,
    minMs: 100,
    maxMs: 400,
    averageMs: 250,
    p50Ms: 200,
    p95Ms: 400,
  });
  assert.deepEqual(analysis.findings, []);
});

test("analyzeLatency emits findings for slow DNS, TCP, TLS, and HTTP p95", () => {
  const analysis = analyzeLatency({
    dns: okResult("example.com", 700, {
      hostname: "example.com",
      ipv4: ["93.184.216.34"],
      ipv6: [],
      addresses: ["93.184.216.34"],
    }),
    tcp: okResult("example.com:443", 1200, {
      hostname: "example.com",
      port: 443,
      connected: true,
    }),
    tls: okResult("example.com:443", 1500, {
      hostname: "example.com",
      port: 443,
      authorized: true,
    }),
    httpRuns: [
      httpOk("https://example.com", 900, 300),
      httpOk("https://example.com", 1400, 500),
    ],
  });

  assert.deepEqual(
    analysis.findings.map((finding) => finding.code),
    [
      "HIGH_HTTP_LATENCY",
      "HIGH_DNS_LATENCY",
      "HIGH_TCP_LATENCY",
      "HIGH_TLS_LATENCY",
    ],
  );
});
