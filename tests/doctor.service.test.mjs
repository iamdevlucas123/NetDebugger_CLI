import assert from "node:assert/strict";
import test from "node:test";

import { InvalidUrlError } from "../dist/core/errors.js";
import { createOkResult } from "../dist/core/result.js";
import { runDoctor } from "../dist/services/doctor.service.js";

// Creates a successful DNS probe result for service orchestration tests.
function dnsOk(hostname) {
  return createOkResult({
    target: hostname,
    durationMs: 1,
    data: {
      hostname,
      ipv4: ["93.184.216.34"],
      ipv6: [],
      addresses: ["93.184.216.34"],
    },
  });
}

// Creates a successful TCP probe result for service orchestration tests.
function tcpOk(hostname, port) {
  return createOkResult({
    target: `${hostname}:${port}`,
    durationMs: 2,
    data: {
      hostname,
      port,
      connected: true,
    },
  });
}

// Creates a successful TLS probe result for service orchestration tests.
function tlsOk(hostname, port) {
  return createOkResult({
    target: `${hostname}:${port}`,
    durationMs: 3,
    data: {
      hostname,
      port,
      authorized: true,
      protocol: "TLSv1.3",
      cipher: "TLS_AES_256_GCM_SHA384",
    },
  });
}

// Creates a successful HTTP probe result with configurable duration.
function httpOk(url, durationMs) {
  return createOkResult({
    target: url,
    durationMs,
    data: {
      url,
      finalUrl: url,
      method: "GET",
      statusCode: 200,
      statusText: "OK",
      headers: {
        "content-type": "text/html",
        "cache-control": "private",
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
      },
      redirects: [],
      timing: {
        startAt: "2026-07-03T00:00:00.000Z",
        totalMs: durationMs,
      },
    },
  });
}

test("runDoctor orchestrates HTTPS probes, analyzers, and latency samples", async () => {
  const order = [];
  const httpDurations = [120, 240, 360];

  const report = await runDoctor(
    "https://example.com/api",
    {
      runs: 3,
      timeoutMs: 3000,
    },
    {
      resolveDns: async (hostname) => {
        order.push("dns");
        assert.equal(hostname, "example.com");
        return dnsOk(hostname);
      },
      connectTcp: async (hostname, port, options) => {
        order.push("tcp");
        assert.equal(hostname, "example.com");
        assert.equal(port, 443);
        assert.equal(options.timeoutMs, 3000);
        return tcpOk(hostname, port);
      },
      probeTls: async (hostname, port, options) => {
        order.push("tls");
        assert.equal(hostname, "example.com");
        assert.equal(port, 443);
        assert.equal(options.timeoutMs, 3000);
        return tlsOk(hostname, port);
      },
      probeHttp: async (url, options) => {
        order.push("http");
        assert.equal(url, "https://example.com/api");
        assert.equal(options.timeoutMs, 3000);
        return httpOk(url, httpDurations.shift());
      },
      analyzeHeaders: (headers) => {
        order.push("headers");
        assert.equal(headers["content-type"], "text/html");
        return {
          headers: [],
          cookieIssues: [],
          findings: [],
        };
      },
      analyzeSecurityHeaders: (headers) => {
        order.push("security");
        assert.equal(headers["x-content-type-options"], "nosniff");
        return {
          checks: [],
          findings: [],
        };
      },
      analyzeLatency: ({ dns, tcp, tls, httpRuns }) => {
        order.push("latency");
        assert.equal(dns.durationMs, 1);
        assert.equal(tcp.durationMs, 2);
        assert.equal(tls.durationMs, 3);
        assert.equal(httpRuns.length, 3);

        return {
          phases: {
            dnsLookupMs: 1,
            tcpConnectMs: 2,
            tlsHandshakeMs: 3,
            httpTotalMs: 360,
          },
          stats: {
            samples: 3,
            minMs: 120,
            maxMs: 360,
            averageMs: 240,
            p50Ms: 240,
            p95Ms: 360,
          },
          findings: [],
        };
      },
      analyzeDiagnosis: ({ dns, tcp, tls, http }) => {
        order.push("diagnosis");
        assert.equal(dns.status, "ok");
        assert.equal(tcp.status, "ok");
        assert.equal(tls.status, "ok");
        assert.equal(http.status, "ok");

        return {
          status: "ok",
          score: 100,
          mainIssue: "No major issue detected.",
          findings: [
            {
              severity: "info",
              code: "DIAGNOSIS_HEALTHY",
              message: "No major issue detected.",
              source: "doctor",
            },
          ],
        };
      },
      now: () => new Date("2026-07-03T00:00:00.000Z"),
    },
  );

  assert.deepEqual(order, [
    "dns",
    "tcp",
    "tls",
    "http",
    "http",
    "http",
    "headers",
    "security",
    "latency",
    "diagnosis",
  ]);
  assert.equal(report.result.ok, true);
  assert.equal(report.result.target.protocol, "https:");
  assert.equal(report.result.target.hostname, "example.com");
  assert.equal(report.result.target.port, 443);
  assert.equal(report.httpRuns.length, 3);
  assert.equal(report.result.latency.samples, 3);
  assert.equal(report.result.latency.averageMs, 240);
  assert.equal(report.result.latency.p95Ms, 360);
  assert.equal(report.result.probes.tls.status, "ok");
  assert.equal(report.headerAnalysis.findings.length, 0);
  assert.equal(report.securityHeaderAnalysis.findings.length, 0);
  assert.equal(report.latencyAnalysis.phases.dnsLookupMs, 1);
  assert.equal(report.diagnosisAnalysis.score, 100);
});

test("runDoctor skips TLS for HTTP targets", async () => {
  const report = await runDoctor(
    "http://example.com/status",
    {},
    {
      resolveDns: async (hostname) => dnsOk(hostname),
      connectTcp: async (hostname, port) => tcpOk(hostname, port),
      probeTls: async () => {
        throw new Error("TLS should not run for HTTP targets.");
      },
      probeHttp: async (url) => httpOk(url, 50),
      analyzeHeaders: () => ({
        headers: [],
        cookieIssues: [],
        findings: [],
      }),
      analyzeSecurityHeaders: () => ({
        checks: [],
        findings: [],
      }),
    },
  );

  assert.equal(report.result.target.expectsTls, false);
  assert.equal(report.result.target.port, 80);
  assert.equal(report.result.probes.tls, undefined);
  assert.equal(report.result.probes.http.status, "ok");
});

test("runDoctor defaults missing protocol inputs to HTTPS", async () => {
  const report = await runDoctor(
    "example.com/path",
    {},
    {
      resolveDns: async (hostname) => dnsOk(hostname),
      connectTcp: async (hostname, port) => tcpOk(hostname, port),
      probeTls: async (hostname, port) => tlsOk(hostname, port),
      probeHttp: async (url) => httpOk(url, 50),
      analyzeHeaders: () => ({
        headers: [],
        cookieIssues: [],
        findings: [],
      }),
      analyzeSecurityHeaders: () => ({
        checks: [],
        findings: [],
      }),
    },
  );

  assert.equal(report.result.target.input, "example.com/path");
  assert.equal(report.result.target.href, "https://example.com/path");
  assert.equal(report.result.target.protocol, "https:");
  assert.equal(report.result.target.port, 443);
  assert.equal(report.result.target.path, "/path");
  assert.equal(report.result.target.expectsTls, true);
});

test("runDoctor rejects unsupported or invalid URLs", async () => {
  await assert.rejects(
    () => runDoctor("://not-a-url"),
    InvalidUrlError,
  );

  await assert.rejects(
    () => runDoctor("ftp://example.com"),
    InvalidUrlError,
  );
});
