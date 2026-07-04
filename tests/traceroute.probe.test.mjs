import assert from "node:assert/strict";
import test from "node:test";

import { probeTraceroute } from "../dist/probes/traceroute.probe.js";

test("probeTraceroute parses Unix traceroute hops", async () => {
  const stdout = [
    "traceroute to example.com (93.184.216.34), 30 hops max",
    " 1  192.168.1.1  1.123 ms  1.012 ms  0.998 ms",
    " 2  10.0.0.1  8.500 ms  8.400 ms  8.300 ms",
    " 3  example.com  20.100 ms  20.200 ms  20.300 ms",
  ].join("\n");
  const result = await probeTraceroute(
    "example.com",
    {
      platform: "unix",
      timeoutMs: 1000,
    },
    {
      execFile: (command, args, _options, callback) => {
        assert.equal(command, "traceroute");
        assert.deepEqual(args, ["example.com"]);
        callback(null, stdout, "");
      },
      now: () => 100,
    },
  );

  assert.equal(result.status, "ok");
  assert.equal(result.data.command, "traceroute");
  assert.equal(result.data.hops.length, 3);
  assert.equal(result.data.hops[0].hop, 1);
  assert.match(result.data.hops[2].output, /example\.com/);
});

test("probeTraceroute uses Windows tracert command", async () => {
  const stdout = [
    "Tracing route to example.com [93.184.216.34]",
    "  1    <1 ms    <1 ms    <1 ms  192.168.1.1",
    "  2    10 ms    11 ms    10 ms  example.com [93.184.216.34]",
  ].join("\r\n");
  const result = await probeTraceroute(
    "example.com",
    {
      platform: "windows",
      timeoutMs: 1000,
    },
    {
      execFile: (command, args, _options, callback) => {
        assert.equal(command, "tracert");
        assert.deepEqual(args, ["example.com"]);
        callback(null, stdout, "");
      },
      now: () => 100,
    },
  );

  assert.equal(result.status, "ok");
  assert.equal(result.data.command, "tracert");
  assert.equal(result.data.hops.length, 2);
});

test("probeTraceroute returns structured command errors", async () => {
  const result = await probeTraceroute(
    "example.com",
    {
      platform: "unix",
      timeoutMs: 1000,
    },
    {
      execFile: (_command, _args, _options, callback) => {
        callback({ code: 1, message: "traceroute failed" }, "", "blocked");
      },
      now: () => 100,
    },
  );

  assert.equal(result.status, "error");
  assert.equal(result.error.code, "TRACEROUTE_ERROR");
  assert.equal(result.error.details.stderr, "blocked");
});

test("probeTraceroute returns timeout errors from the command runner", async () => {
  const result = await probeTraceroute(
    "example.com",
    {
      platform: "unix",
      timeoutMs: 20,
    },
    {
      execFile: (_command, _args, _options, callback) => {
        callback({ killed: true, message: "command timed out" }, "", "");
      },
      now: () => 100,
    },
  );

  assert.equal(result.status, "error");
  assert.equal(result.error.code, "TIMEOUT_ERROR");
});
