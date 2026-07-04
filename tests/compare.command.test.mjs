import assert from "node:assert/strict";
import test from "node:test";

import {
  buildCompareReport,
  renderCompareReport,
} from "../dist/commands/compare.command.js";
import { createOkResult } from "../dist/core/result.js";

// Creates a minimal doctor report for compare command tests.
function createReport({
  label,
  url,
  statusCode,
  p95Ms,
  averageMs,
  hsts,
  server,
  contentType,
  tlsVersion,
  redirects,
  securityStatus,
}) {
  const http = createOkResult({
    target: url,
    durationMs: averageMs,
    data: {
      url,
      finalUrl: url,
      method: "GET",
      statusCode,
      statusText: statusCode >= 500 ? "Internal Server Error" : "OK",
      headers: {
        server,
        "content-type": contentType,
        ...(hsts ? { "strict-transport-security": "max-age=31536000" } : {}),
      },
      redirects: Array.from({ length: redirects }, (_value, index) => ({
        statusCode: 302,
        location: `/redirect-${index}`,
      })),
      timing: {
        startAt: "2026-07-03T00:00:00.000Z",
        totalMs: averageMs,
      },
    },
  });
  const tls = createOkResult({
    target: new URL(url).hostname,
    durationMs: 20,
    data: {
      hostname: new URL(url).hostname,
      port: 443,
      authorized: true,
      protocol: tlsVersion,
    },
  });

  return {
    result: {
      command: "doctor",
      target: {
        input: url,
        protocol: "https:",
        hostname: new URL(url).hostname,
        port: 443,
        path: "/",
        href: url,
        expectsTls: true,
      },
      ok: statusCode < 500,
      startedAt: "2026-07-03T00:00:00.000Z",
      completedAt: "2026-07-03T00:00:00.100Z",
      durationMs: averageMs,
      probes: {
        http,
        tls,
      },
      latency: {
        samples: 3,
        minMs: averageMs - 20,
        maxMs: p95Ms,
        averageMs,
        p50Ms: averageMs,
        p95Ms,
      },
      findings: [],
    },
    httpRuns: [http],
    securityHeaderAnalysis: {
      checks: [
        {
          name: "strict-transport-security",
          label: "HSTS",
          status: securityStatus,
          value: hsts ? "max-age=31536000" : null,
          message: "HSTS status.",
        },
      ],
      findings: [],
    },
    diagnosisAnalysis: {
      status: statusCode >= 500 ? "error" : "ok",
      score: statusCode >= 500 ? 70 : 100,
      mainIssue: `${label} issue`,
      findings: [],
    },
  };
}

test("buildCompareReport reports status, latency, security, and header differences", () => {
  const production = createReport({
    label: "Production",
    url: "https://api.example.com/",
    statusCode: 200,
    p95Ms: 180,
    averageMs: 120,
    hsts: true,
    server: "nginx",
    contentType: "application/json",
    tlsVersion: "TLSv1.3",
    redirects: 0,
    securityStatus: "OK",
  });
  const staging = createReport({
    label: "Staging",
    url: "https://staging.example.com/",
    statusCode: 500,
    p95Ms: 920,
    averageMs: 600,
    hsts: false,
    server: "apache",
    contentType: "text/html",
    tlsVersion: "TLSv1.2",
    redirects: 2,
    securityStatus: "ERROR",
  });

  const report = buildCompareReport(production, staging);

  assert.equal(report.left.statusCode, 200);
  assert.equal(report.right.statusCode, 500);
  assert.equal(report.left.hstsEnabled, true);
  assert.equal(report.right.hstsEnabled, false);
  assert.deepEqual(report.differences, [
    "Right returns 500 while Left returns 200.",
    "Right is slower by 740ms p95.",
    "TLS differs: Left uses TLSv1.3, Right uses TLSv1.2.",
    "Redirects differ: Left has 0, Right has 2.",
    "Server header differs: nginx vs apache.",
    "Content-Type differs: application/json vs text/html.",
    "HSTS differs: Left is enabled, Right is missing.",
    "Security headers differ.",
  ]);
});

test("renderCompareReport prints concise summaries and differences", () => {
  const report = {
    left: {
      label: "Left",
      target: "https://api.example.com/",
      statusCode: 200,
      averageMs: 120,
      p95Ms: 180,
      tlsVersion: "TLSv1.3",
      tlsAuthorized: true,
      redirects: 0,
      server: "nginx",
      contentType: "application/json",
      hstsEnabled: true,
      securityHeaders: {},
    },
    right: {
      label: "Right",
      target: "https://staging.example.com/",
      statusCode: 500,
      averageMs: 600,
      p95Ms: 920,
      tlsVersion: "TLSv1.2",
      tlsAuthorized: true,
      redirects: 2,
      server: "apache",
      contentType: "text/html",
      hstsEnabled: false,
      securityHeaders: {},
    },
    differences: ["Right returns 500 while Left returns 200."],
  };

  const output = renderCompareReport(report);

  assert.match(output, /Left: 200 - p95 180ms - HSTS enabled - TLS TLSv1\.3/);
  assert.match(output, /Right: 500 - p95 920ms - HSTS missing - TLS TLSv1\.2/);
  assert.match(output, /Differences:/);
  assert.match(output, /Right returns 500/);
});
