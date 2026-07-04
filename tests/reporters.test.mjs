import assert from "node:assert/strict";
import test from "node:test";

import { renderDoctorConsoleReport } from "../dist/output/console.reporter.js";
import {
  buildDoctorJsonPayload,
  renderDoctorJsonReport,
} from "../dist/output/json.reporter.js";
import { renderDoctorTable } from "../dist/output/table.reporter.js";
import { createOkResult } from "../dist/core/result.js";

// Creates a deterministic doctor report for reporter tests.
function createReport() {
  const dns = createOkResult({
    target: "example.com",
    durationMs: 24,
    data: {
      hostname: "example.com",
      ipv4: ["93.184.216.34"],
      ipv6: ["2606:2800:220:1:248:1893:25c8:1946"],
      addresses: ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"],
    },
  });
  const tcp = createOkResult({
    target: "example.com:443",
    durationMs: 81,
    data: {
      hostname: "example.com",
      port: 443,
      connected: true,
    },
  });
  const tls = createOkResult({
    target: "example.com:443",
    durationMs: 92,
    data: {
      hostname: "example.com",
      port: 443,
      authorized: true,
      protocol: "TLSv1.3",
    },
  });
  const http = createOkResult({
    target: "https://example.com",
    durationMs: 132,
    data: {
      url: "https://example.com",
      finalUrl: "https://example.com",
      method: "GET",
      statusCode: 200,
      statusText: "OK",
      headers: {
        "content-type": "text/html",
        server: "nginx",
      },
      redirects: [],
      timing: {
        startAt: "2026-07-03T00:00:00.000Z",
        totalMs: 132,
      },
    },
  });
  const warning = {
    severity: "warning",
    code: "SECURITY_HEADER_CONTENT_SECURITY_POLICY",
    message: "CSP header is missing.",
    recommendation: "Add a Content-Security-Policy header.",
    source: "analyzer",
  };

  return {
    result: {
      command: "doctor",
      target: {
        input: "https://example.com",
        protocol: "https:",
        hostname: "example.com",
        port: 443,
        path: "/",
        href: "https://example.com/",
        expectsTls: true,
      },
      ok: true,
      startedAt: "2026-07-03T00:00:00.000Z",
      completedAt: "2026-07-03T00:00:00.132Z",
      durationMs: 132,
      probes: {
        dns,
        tcp,
        tls,
        http,
      },
      latency: {
        samples: 1,
        minMs: 132,
        maxMs: 132,
        averageMs: 132,
        p50Ms: 132,
        p95Ms: 132,
      },
      findings: [
        warning,
        {
          severity: "info",
          code: "DOCTOR_COMPLETED",
          message: "Doctor completed.",
          source: "doctor",
        },
      ],
    },
    httpRuns: [http],
    headerAnalysis: {
      headers: [],
      cookieIssues: [],
      findings: [],
    },
    securityHeaderAnalysis: {
      checks: [],
      findings: [warning],
    },
    latencyAnalysis: {
      phases: {
        dnsLookupMs: 24,
        tcpConnectMs: 81,
        tlsHandshakeMs: 92,
        httpTotalMs: 132,
      },
      stats: {
        samples: 1,
        minMs: 132,
        maxMs: 132,
        averageMs: 132,
        p50Ms: 132,
        p95Ms: 132,
      },
      findings: [],
    },
    diagnosisAnalysis: {
      status: "warn",
      score: 95,
      mainIssue: "Content-Security-Policy is missing.",
      findings: [
        {
          severity: "warning",
          code: "DIAGNOSIS_CSP_MISSING",
          message: "Content-Security-Policy is missing.",
          source: "doctor",
        },
      ],
    },
  };
}

test("renderDoctorTable prints the diagnostic rows", () => {
  const output = renderDoctorTable(createReport());

  assert.match(output, /Test/);
  assert.match(output, /DNS/);
  assert.match(output, /2 records/);
  assert.match(output, /TCP/);
  assert.match(output, /port open/);
  assert.match(output, /TLSv1\.3/);
  assert.match(output, /CSP header is missing/);
});

test("buildDoctorJsonPayload returns stable automation fields", () => {
  const payload = buildDoctorJsonPayload(createReport());

  assert.equal(payload.target, "https://example.com/");
  assert.equal(payload.status, "warn");
  assert.equal(payload.score, 95);
  assert.equal(payload.mainIssue, "Content-Security-Policy is missing.");
  assert.equal(payload.dns.status, "ok");
  assert.equal(payload.tcp.status, "ok");
  assert.equal(payload.tls.status, "ok");
  assert.equal(payload.http.status, "ok");
  assert.equal(payload.headers.security.findings.length, 1);
  assert.equal(payload.diagnosis.length, 1);
  assert.equal(payload.diagnosis[0].code, "DIAGNOSIS_CSP_MISSING");
});

test("renderDoctorJsonReport prints formatted JSON", () => {
  const json = renderDoctorJsonReport(createReport());
  const payload = JSON.parse(json);

  assert.equal(payload.target, "https://example.com/");
  assert.equal(payload.status, "warn");
});

test("renderDoctorConsoleReport combines summary, table, latency, and findings", () => {
  const output = renderDoctorConsoleReport(createReport());

  assert.match(output, /Target: https:\/\/example.com\//);
  assert.match(output, /Status: WARN/);
  assert.match(output, /Health Score: 95\/100/);
  assert.match(output, /Main issue: Content-Security-Policy is missing/);
  assert.match(output, /Latency:/);
  assert.match(output, /Findings: 1/);
  assert.match(output, /Possible action: Add a Content-Security-Policy header/);
});

test("renderDoctorConsoleReport can include selected response headers", () => {
  const output = renderDoctorConsoleReport(createReport(), {
    includeHeaders: true,
  });

  assert.match(output, /Headers:/);
  assert.match(output, /Content-Type: text\/html/);
  assert.match(output, /Server: nginx/);
});
