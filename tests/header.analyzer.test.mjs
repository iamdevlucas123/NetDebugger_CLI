import assert from "node:assert/strict";
import test from "node:test";

import { analyzeHeaders } from "../dist/analyzers/header.analyzer.js";

test("analyzeHeaders reports useful common header information", () => {
  const result = analyzeHeaders({
    "Content-Type": "text/html",
    "Cache-Control": "private, max-age=0",
    Server: "nginx",
    Location: "https://example.com/new",
  });

  assert.deepEqual(
    result.headers.map((header) => [header.name, header.value]),
    [
      ["content-type", "text/html"],
      ["cache-control", "private, max-age=0"],
      ["set-cookie", "missing"],
      ["server", "nginx"],
      ["location", "https://example.com/new"],
    ],
  );
  assert.equal(result.cookieIssues.length, 0);
  assert.equal(
    result.findings.some((finding) => finding.code === "SERVER_HEADER_EXPOSED"),
    true,
  );
});

test("analyzeHeaders detects cookies missing security attributes", () => {
  const result = analyzeHeaders({
    "Set-Cookie": ["session=abc; Path=/"],
    "Cache-Control": "no-store",
  });

  assert.equal(result.cookieIssues.length, 1);
  assert.deepEqual(result.cookieIssues[0].missing, [
    "HttpOnly",
    "Secure",
    "SameSite",
  ]);
  assert.equal(result.findings[0].code, "COOKIE_SECURITY_ATTRIBUTES_MISSING");
});

test("analyzeHeaders detects weak or missing cache control", () => {
  const weakResult = analyzeHeaders({
    "Cache-Control": "public, max-age=3600",
  });
  const missingResult = analyzeHeaders({});

  assert.equal(weakResult.findings[0].code, "CACHE_CONTROL_WEAK");
  assert.equal(missingResult.findings[0].code, "CACHE_CONTROL_MISSING");
});
