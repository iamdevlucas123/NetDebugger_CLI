import assert from "node:assert/strict";
import test from "node:test";

import {
  buildCurlHeadArgs,
  parseCurlHeaderBlocks,
  runCurlHead,
} from "../dist/adapters/curl.adapter.js";

test("buildCurlHeadArgs builds curl HEAD redirect arguments", () => {
  assert.deepEqual(buildCurlHeadArgs("https://example.com"), [
    "-I",
    "-L",
    "https://example.com",
  ]);
  assert.deepEqual(buildCurlHeadArgs("https://example.com", { maxRedirects: 3 }), [
    "-I",
    "-L",
    "--max-redirs",
    "3",
    "https://example.com",
  ]);
});

test("parseCurlHeaderBlocks parses redirect and final response headers", () => {
  const blocks = parseCurlHeaderBlocks(
    [
      "HTTP/1.1 301 Moved Permanently",
      "Location: https://www.example.com/",
      "Server: edge",
      "",
      "HTTP/2 200",
      "Content-Type: text/html",
      "Server: app",
      "Set-Cookie: a=1",
      "Set-Cookie: b=2",
      "",
    ].join("\n"),
  );

  assert.equal(blocks.length, 2);
  assert.equal(blocks[0].statusCode, 301);
  assert.deepEqual(blocks[0].headers.location, ["https://www.example.com/"]);
  assert.equal(blocks[1].statusCode, 200);
  assert.deepEqual(blocks[1].headers["set-cookie"], ["a=1", "b=2"]);
});

test("runCurlHead executes curl through the command runner dependency", async () => {
  const stdout = [
    "HTTP/2 200",
    "Content-Type: text/html",
    "",
  ].join("\n");
  const result = await runCurlHead(
    "https://example.com",
    {
      timeoutMs: 5000,
      maxRedirects: 5,
    },
    {
      execFile: (file, args, options, callback) => {
        assert.equal(file, "curl");
        assert.deepEqual(args, [
          "-I",
          "-L",
          "--max-redirs",
          "5",
          "https://example.com",
        ]);
        assert.equal(options.timeout, 5000);
        callback(null, stdout, "");
      },
    },
  );

  assert.equal(result.ok, true);
  assert.equal(result.command, "curl");
  assert.equal(result.exitCode, 0);
  assert.equal(result.headerBlocks[0].statusCode, 200);
});

test("runCurlHead returns failed curl executions without throwing", async () => {
  const result = await runCurlHead(
    "https://example.com",
    {},
    {
      execFile: (_file, _args, _options, callback) => {
        callback({ code: 6, message: "Could not resolve host" }, "", "curl error");
      },
    },
  );

  assert.equal(result.ok, false);
  assert.equal(result.exitCode, 6);
  assert.equal(result.stderr, "curl error");
  assert.equal(result.errorMessage, "Could not resolve host");
});
