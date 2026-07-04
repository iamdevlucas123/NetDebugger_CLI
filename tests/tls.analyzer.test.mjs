import assert from "node:assert/strict";
import test from "node:test";

import { analyzeTlsCertificate } from "../dist/analyzers/tls.analyzer.js";

// Creates minimal TLS probe data for analyzer tests.
function createTlsData(validTo) {
  return {
    hostname: "example.com",
    port: 443,
    authorized: true,
    certificate: {
      validTo,
    },
  };
}

test("analyzeTlsCertificate reports healthy certificates without findings", () => {
  const result = analyzeTlsCertificate(createTlsData("2026-09-20T00:00:00.000Z"), {
    now: new Date("2026-06-30T00:00:00.000Z"),
  });

  assert.equal(result.daysLeft, 82);
  assert.equal(result.expired, false);
  assert.equal(result.expiringSoon, false);
  assert.deepEqual(result.findings, []);
});

test("analyzeTlsCertificate warns when certificate is close to expiration", () => {
  const result = analyzeTlsCertificate(createTlsData("2026-07-10T00:00:00.000Z"), {
    now: new Date("2026-06-30T00:00:00.000Z"),
  });

  assert.equal(result.daysLeft, 10);
  assert.equal(result.expired, false);
  assert.equal(result.expiringSoon, true);
  assert.equal(result.findings[0].code, "TLS_CERTIFICATE_EXPIRING_SOON");
});

test("analyzeTlsCertificate marks expired certificates as critical", () => {
  const result = analyzeTlsCertificate(createTlsData("2026-06-01T00:00:00.000Z"), {
    now: new Date("2026-06-30T00:00:00.000Z"),
  });

  assert.equal(result.daysLeft, -29);
  assert.equal(result.expired, true);
  assert.equal(result.findings[0].severity, "critical");
  assert.equal(result.findings[0].code, "TLS_CERTIFICATE_EXPIRED");
  assert.equal(result.findings[0].message, "TLS certificate expired 29 day(s) ago.");
});
