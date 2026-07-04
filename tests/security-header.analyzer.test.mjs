import assert from "node:assert/strict";
import test from "node:test";

import { analyzeSecurityHeaders } from "../dist/analyzers/security-header.analyzer.js";

test("analyzeSecurityHeaders marks present security headers as OK", () => {
  const result = analyzeSecurityHeaders({
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
  });

  assert.equal(result.checks.every((check) => check.status === "OK"), true);
  assert.deepEqual(result.findings, []);
});

test("analyzeSecurityHeaders classifies missing headers as warnings or errors", () => {
  const result = analyzeSecurityHeaders({
    "X-Content-Type-Options": "nosniff",
  });
  const csp = result.checks.find((check) => check.label === "CSP");
  const hsts = result.checks.find((check) => check.label === "HSTS");
  const frameOptions = result.checks.find(
    (check) => check.label === "X-Frame-Options",
  );

  assert.equal(csp?.status, "ERROR");
  assert.equal(hsts?.status, "ERROR");
  assert.equal(frameOptions?.status, "WARN");
  assert.equal(
    result.findings.some(
      (finding) => finding.code === "SECURITY_HEADER_CONTENT_SECURITY_POLICY",
    ),
    true,
  );
});

test("analyzeSecurityHeaders reports missing CSP as a critical finding", () => {
  const result = analyzeSecurityHeaders({
    "Strict-Transport-Security": "max-age=31536000",
    "X-Content-Type-Options": "nosniff",
  });
  const finding = result.findings.find(
    (item) => item.code === "SECURITY_HEADER_CONTENT_SECURITY_POLICY",
  );

  assert.equal(finding?.severity, "critical");
  assert.equal(finding?.message, "CSP header is missing.");
});

test("analyzeSecurityHeaders flags invalid X-Content-Type-Options", () => {
  const result = analyzeSecurityHeaders({
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000",
    "X-Content-Type-Options": "none",
  });
  const contentTypeOptions = result.checks.find(
    (check) => check.label === "X-Content-Type-Options",
  );

  assert.equal(contentTypeOptions?.status, "ERROR");
  assert.equal(
    contentTypeOptions?.message,
    "X-Content-Type-Options header should be nosniff.",
  );
});
