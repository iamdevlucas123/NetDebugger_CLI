import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { createServer } from "node:net";
import test from "node:test";

import { connectTcp } from "../dist/probes/tcp.probe.js";

// Creates a deterministic clock for probe duration assertions.
function createClock(values) {
  let index = 0;

  return () => values[index++] ?? values[values.length - 1] ?? 0;
}

// Starts a local TCP server and returns its selected port.
async function listenOnLocalhost(server) {
  await new Promise((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });

  const address = server.address();

  assert.equal(typeof address, "object");
  assert.notEqual(address, null);

  return address.port;
}

// Stops a TCP server after a test completes.
async function closeServer(server) {
  if (!server.listening) {
    return;
  }

  await new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }

      resolve();
    });
  });
}

class TimeoutSocket extends EventEmitter {
  remoteAddress = undefined;
  remoteFamily = undefined;
  timeoutHandler = undefined;
  destroyed = false;

  // Stores the timeout callback configured by the TCP probe.
  setTimeout(_timeoutMs, handler) {
    this.timeoutHandler = handler;
    return this;
  }

  // Simulates a socket connection attempt that reaches the timeout callback.
  connect(_options) {
    setImmediate(() => {
      this.timeoutHandler?.();
    });
    return this;
  }

  // Marks the fake socket as destroyed after the probe settles.
  destroy() {
    this.destroyed = true;
    return this;
  }
}

test("connectTcp returns ok when a local TCP server accepts the connection", async () => {
  const server = createServer((socket) => {
    socket.end();
  });

  const port = await listenOnLocalhost(server);

  try {
    const result = await connectTcp("127.0.0.1", port, { timeoutMs: 1000 });

    assert.equal(result.status, "ok");
    assert.equal(result.target, `127.0.0.1:${port}`);
    assert.equal(result.error, null);
    assert.equal(result.data.hostname, "127.0.0.1");
    assert.equal(result.data.port, port);
    assert.equal(result.data.connected, true);
    assert.equal(typeof result.durationMs, "number");
  } finally {
    await closeServer(server);
  }
});

test("connectTcp returns error when a local TCP port is closed", async () => {
  const server = createServer();
  const port = await listenOnLocalhost(server);
  await closeServer(server);

  const result = await connectTcp("127.0.0.1", port, { timeoutMs: 1000 });

  assert.equal(result.status, "error");
  assert.equal(result.target, `127.0.0.1:${port}`);
  assert.equal(result.data, null);
  assert.equal(result.error.code, "TCP_CONNECTION_ERROR");
});

test("connectTcp returns timeout error when the socket times out", async () => {
  const fakeSocket = new TimeoutSocket();

  const result = await connectTcp(
    "timeout.example",
    443,
    { timeoutMs: 50 },
    {
      createSocket: () => fakeSocket,
      now: createClock([10, 60]),
    },
  );

  assert.equal(result.status, "error");
  assert.equal(result.target, "timeout.example:443");
  assert.equal(result.durationMs, 50);
  assert.equal(result.data, null);
  assert.equal(result.error.code, "TIMEOUT_ERROR");
  assert.equal(fakeSocket.destroyed, true);
});
