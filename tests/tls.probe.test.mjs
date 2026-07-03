import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

import { probeTls } from "../dist/probes/tls.probe.js";

// Creates a deterministic clock for probe duration assertions.
function createClock(values) {
  let index = 0;

  return () => values[index++] ?? values[values.length - 1] ?? 0;
}

class FakeTlsSocket extends EventEmitter {
  authorized = true;
  authorizationError = undefined;
  destroyed = false;
  timeoutHandler = undefined;

  // Returns the negotiated TLS protocol for probe output.
  getProtocol() {
    return "TLSv1.3";
  }

  // Returns the negotiated cipher for probe output.
  getCipher() {
    return {
      standardName: "TLS_AES_256_GCM_SHA384",
    };
  }

  // Returns a serializable certificate fixture for probe output.
  getPeerCertificate(_detailed) {
    return {
      subject: { CN: "example.com" },
      issuer: { O: "DigiCert" },
      valid_from: "Jun 30 00:00:00 2026 GMT",
      valid_to: "Sep 20 00:00:00 2026 GMT",
      fingerprint: "AA:BB",
      subjectaltname: "DNS:example.com",
    };
  }

  // Stores the timeout callback configured by the TLS probe.
  setTimeout(_timeoutMs, callback) {
    this.timeoutHandler = callback;
    return this;
  }

  // Marks the fake socket as destroyed after the probe settles.
  destroy() {
    this.destroyed = true;
  }
}

// Creates a fake tls.connect function that completes the handshake.
function createSuccessfulConnect(socket) {
  return (_options, callback) => {
    setImmediate(callback);
    return socket;
  };
}

// Creates a fake tls.connect function that emits an error.
function createFailingConnect(socket) {
  return (_options, _callback) => {
    setImmediate(() => {
      socket.emit("error", new Error("handshake failed"));
    });
    return socket;
  };
}

// Creates a fake tls.connect function that triggers a timeout.
function createTimeoutConnect(socket) {
  return (_options, _callback) => {
    setImmediate(() => {
      socket.timeoutHandler?.();
    });
    return socket;
  };
}

test("probeTls returns ok when TLS handshake succeeds", async () => {
  const socket = new FakeTlsSocket();

  const result = await probeTls(
    "example.com",
    443,
    { timeoutMs: 1000 },
    {
      connect: createSuccessfulConnect(socket),
      now: createClock([100, 178]),
    },
  );

  assert.equal(result.status, "ok");
  assert.equal(result.target, "example.com:443");
  assert.equal(result.durationMs, 78);
  assert.equal(result.error, null);
  assert.equal(result.data.protocol, "TLSv1.3");
  assert.equal(result.data.cipher, "TLS_AES_256_GCM_SHA384");
  assert.equal(result.data.certificate?.issuer, "DigiCert");
  assert.equal(result.data.certificate?.subject, "example.com");
  assert.equal(socket.destroyed, true);
});

test("probeTls returns error when TLS handshake fails", async () => {
  const socket = new FakeTlsSocket();

  const result = await probeTls(
    "example.com",
    443,
    { timeoutMs: 1000 },
    {
      connect: createFailingConnect(socket),
      now: createClock([200, 230]),
    },
  );

  assert.equal(result.status, "error");
  assert.equal(result.target, "example.com:443");
  assert.equal(result.durationMs, 30);
  assert.equal(result.error.code, "TLS_HANDSHAKE_ERROR");
});

test("probeTls returns timeout error when handshake times out", async () => {
  const socket = new FakeTlsSocket();

  const result = await probeTls(
    "example.com",
    443,
    { timeoutMs: 50 },
    {
      connect: createTimeoutConnect(socket),
      now: createClock([300, 350]),
    },
  );

  assert.equal(result.status, "error");
  assert.equal(result.target, "example.com:443");
  assert.equal(result.durationMs, 50);
  assert.equal(result.error.code, "TIMEOUT_ERROR");
});
