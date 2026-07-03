import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";

import { probeHttp } from "../dist/probes/http.probe.js";

// Starts a local HTTP server and returns its selected URL.
async function listenOnLocalhost(server) {
  await new Promise((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });

  const address = server.address();

  assert.equal(typeof address, "object");
  assert.notEqual(address, null);

  return `http://127.0.0.1:${address.port}`;
}

// Stops an HTTP server after a test completes.
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

test("probeHttp returns status, headers, and total timing", async () => {
  const server = createServer((_request, response) => {
    response.writeHead(200, {
      "Content-Type": "text/html",
      Server: "local-test",
    });
    response.end("<html></html>");
  });
  const baseUrl = await listenOnLocalhost(server);

  try {
    const result = await probeHttp(baseUrl);

    assert.equal(result.status, "ok");
    assert.equal(result.data.statusCode, 200);
    assert.equal(result.data.statusText, "OK");
    assert.equal(result.data.headers["content-type"], "text/html");
    assert.equal(result.data.headers.server, "local-test");
    assert.equal(result.data.redirects.length, 0);
    assert.equal(typeof result.durationMs, "number");
  } finally {
    await closeServer(server);
  }
});

test("probeHttp follows redirects and records them", async () => {
  const server = createServer((request, response) => {
    if (request.url === "/start") {
      response.writeHead(302, { Location: "/final" });
      response.end();
      return;
    }

    response.writeHead(200, { "Content-Type": "text/plain" });
    response.end("done");
  });
  const baseUrl = await listenOnLocalhost(server);

  try {
    const result = await probeHttp(`${baseUrl}/start`);

    assert.equal(result.status, "ok");
    assert.equal(result.data.statusCode, 200);
    assert.equal(result.data.finalUrl, `${baseUrl}/final`);
    assert.deepEqual(result.data.redirects, [
      {
        statusCode: 302,
        location: "/final",
      },
    ]);
  } finally {
    await closeServer(server);
  }
});

test("probeHttp returns timeout error when the server does not respond", async () => {
  const server = createServer((_request, _response) => {
    // Intentionally keep the request open until the client times out.
  });
  const baseUrl = await listenOnLocalhost(server);

  try {
    const result = await probeHttp(baseUrl, { timeoutMs: 20 });

    assert.equal(result.status, "error");
    assert.equal(result.error.code, "TIMEOUT_ERROR");
    assert.equal(result.data, null);
  } finally {
    await closeServer(server);
  }
});

test("probeHttp returns connection error for closed local ports", async () => {
  const server = createServer();
  const baseUrl = await listenOnLocalhost(server);
  const port = new URL(baseUrl).port;

  await closeServer(server);

  const result = await probeHttp(`http://127.0.0.1:${port}`);

  assert.equal(result.status, "error");
  assert.equal(result.error.code, "HTTP_REQUEST_ERROR");
  assert.equal(result.data, null);
});
