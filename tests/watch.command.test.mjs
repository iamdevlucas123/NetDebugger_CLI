import assert from "node:assert/strict";
import test from "node:test";

import {
  buildWatchSnapshot,
  formatWatchLine,
} from "../dist/commands/watch.command.js";
import { createOkResult } from "../dist/core/result.js";

// Creates a doctor report with a configurable HTTP status and duration.
function createReport({ status, statusCode, durationMs, score, mainIssue }) {
  const http = createOkResult({
    target: "https://example.com",
    durationMs,
    data: {
      url: "https://example.com",
      finalUrl: "https://example.com",
      method: "GET",
      statusCode,
      statusText: statusCode >= 500 ? "Service Unavailable" : "OK",
      headers: {},
      redirects: [],
      timing: {
        startAt: "2026-07-03T12:00:00.000Z",
        totalMs: durationMs,
      },
    },
  });

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
      ok: status !== "error",
      startedAt: "2026-07-03T12:00:00.000Z",
      completedAt: "2026-07-03T12:00:00.142Z",
      durationMs,
      probes: {
        http,
      },
      findings: [],
    },
    httpRuns: [http],
    diagnosisAnalysis: {
      status,
      score,
      mainIssue,
      findings: [],
    },
  };
}

test("buildWatchSnapshot captures current status without change on first run", () => {
  const snapshot = buildWatchSnapshot(
    createReport({
      status: "ok",
      statusCode: 200,
      durationMs: 142,
      score: 100,
      mainIssue: "No major issue detected.",
    }),
    undefined,
    new Date("2026-07-03T12:00:00.000Z"),
  );

  assert.equal(snapshot.target, "https://example.com/");
  assert.equal(snapshot.status, "ok");
  assert.equal(snapshot.statusCode, 200);
  assert.equal(snapshot.durationMs, 142);
  assert.equal(snapshot.changed, false);
  assert.equal(snapshot.statusKey, "ok:200");
});

test("buildWatchSnapshot marks status changes between runs", () => {
  const snapshot = buildWatchSnapshot(
    createReport({
      status: "warn",
      statusCode: 503,
      durationMs: 900,
      score: 70,
      mainIssue: "The server responded, but the application is failing.",
    }),
    "ok:200",
    new Date("2026-07-03T12:01:00.000Z"),
  );

  assert.equal(snapshot.changed, true);
  assert.equal(snapshot.previousStatusKey, "ok:200");
  assert.equal(snapshot.statusKey, "warn:503");
});

test("formatWatchLine prints timestamp, status, code, duration, and change marker", () => {
  const line = formatWatchLine({
    target: "https://example.com/",
    status: "warn",
    statusCode: 503,
    durationMs: 900,
    timestamp: "2026-07-03T12:01:00.000Z",
    changed: true,
    previousStatusKey: "ok:200",
    statusKey: "warn:503",
    score: 70,
    mainIssue: "The server responded, but the application is failing.",
  });

  assert.equal(line, "[12:01:00] WARN 503 900ms (changed)");
});
