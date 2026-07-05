import assert from "node:assert/strict";
import test from "node:test";

import { resolveDns } from "../dist/probes/dns.probe.js";

// Creates a deterministic clock for probe duration assertions.
function createClock(values) {
  let index = 0;

  return () => values[index++] ?? values[values.length - 1] ?? 0;
}

// Creates a DNS resolver that returns fixed addresses.
function createSuccessfulResolver(addresses) {
  return async () => addresses;
}

// Creates a DNS resolver that always rejects with a stable DNS error.
function createFailingResolver(message) {
  return async () => {
    throw new Error(message);
  };
}

// Creates a system DNS lookup resolver that returns family-tagged addresses.
function createSuccessfulLookup(addresses) {
  return async () => addresses;
}

test("resolveDns returns ok for a valid domain", async () => {
  const result = await resolveDns("example.com", {
    resolve4: createSuccessfulResolver(["93.184.216.34"]),
    resolve6: createSuccessfulResolver([]),
    now: createClock([100, 122]),
  });

  assert.equal(result.status, "ok");
  assert.equal(result.target, "example.com");
  assert.equal(result.durationMs, 22);
  assert.equal(result.error, null);
  assert.equal(result.data.hostname, "example.com");
  assert.deepEqual(result.data.ipv4, ["93.184.216.34"]);
  assert.deepEqual(result.data.ipv6, []);
  assert.deepEqual(result.data.addresses, ["93.184.216.34"]);
  assert.equal(result.data.resolver, "direct");
});

test("resolveDns returns ok when at least one address family resolves", async () => {
  const result = await resolveDns("example.com", {
    resolve4: createSuccessfulResolver(["93.184.216.34"]),
    resolve6: createFailingResolver("IPv6 lookup failed"),
    now: createClock([300, 315]),
  });

  assert.equal(result.status, "ok");
  assert.equal(result.durationMs, 15);
  assert.deepEqual(result.data.ipv4, ["93.184.216.34"]);
  assert.deepEqual(result.data.ipv6, []);
  assert.deepEqual(result.data.addresses, ["93.184.216.34"]);
  assert.equal(result.data.resolver, "direct");
});

test("resolveDns falls back to the system resolver when direct DNS fails", async () => {
  const result = await resolveDns("google.com", {
    resolve4: createFailingResolver("queryA ECONNREFUSED google.com"),
    resolve6: createFailingResolver("queryAaaa ECONNREFUSED google.com"),
    lookup: createSuccessfulLookup([
      { address: "2800:3f0:4001:838::200e", family: 6 },
    ]),
    now: createClock([500, 505, 509]),
  });

  assert.equal(result.status, "ok");
  assert.equal(result.target, "google.com");
  assert.equal(result.durationMs, 9);
  assert.equal(result.error, null);
  assert.equal(result.data.resolver, "system-fallback");
  assert.deepEqual(result.data.ipv4, []);
  assert.deepEqual(result.data.ipv6, ["2800:3f0:4001:838::200e"]);
  assert.deepEqual(result.data.addresses, ["2800:3f0:4001:838::200e"]);
  assert.match(result.data.warning, /system resolver worked/);
  assert.match(
    result.data.directResolverErrors.ipv4Error,
    /queryA ECONNREFUSED/,
  );
});

test("resolveDns returns error when no DNS records resolve", async () => {
  const result = await resolveDns("missing.example", {
    resolve4: createFailingResolver("IPv4 lookup failed"),
    resolve6: createFailingResolver("IPv6 lookup failed"),
    now: createClock([200, 240]),
  });

  assert.equal(result.status, "error");
  assert.equal(result.target, "missing.example");
  assert.equal(result.durationMs, 40);
  assert.equal(result.data, null);
  assert.equal(result.error.code, "DNS_ERROR");
  assert.match(result.error.message, /DNS lookup failed/);
});
