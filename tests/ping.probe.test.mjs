import assert from "node:assert/strict";
import test from "node:test";

import { probePing } from "../dist/probes/ping.probe.js";

// Creates a fake execFile dependency that returns fixed process output.
function createExecFile(stdout, stderr = "", error = null) {
  return (command, args, _options, callback) => {
    assert.equal(command, "ping");
    assert.deepEqual(args, ["-c", "4", "example.com"]);
    callback(error, stdout, stderr);
  };
}

test("probePing parses Unix ping output", async () => {
  const stdout = [
    "PING example.com (93.184.216.34): 56 data bytes",
    "64 bytes from 93.184.216.34: icmp_seq=0 ttl=56 time=12.3 ms",
    "--- example.com ping statistics ---",
    "4 packets transmitted, 4 received, 0% packet loss",
    "round-trip min/avg/max/stddev = 10.0/12.5/15.0/1.0 ms",
  ].join("\n");
  const result = await probePing(
    "example.com",
    {
      platform: "unix",
      count: 4,
      timeoutMs: 1000,
    },
    {
      execFile: createExecFile(stdout),
      now: () => 100,
    },
  );

  assert.equal(result.status, "ok");
  assert.equal(result.data.transmitted, 4);
  assert.equal(result.data.received, 4);
  assert.equal(result.data.packetLossPercent, 0);
  assert.equal(result.data.averageMs, 12.5);
  assert.equal(result.data.reachable, true);
});

test("probePing parses Windows ping output", async () => {
  const stdout = [
    "Pinging example.com [93.184.216.34] with 32 bytes of data:",
    "Reply from 93.184.216.34: bytes=32 time=18ms TTL=56",
    "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),",
    "Approximate round trip times in milli-seconds:",
    "Minimum = 15ms, Maximum = 20ms, Average = 18ms",
  ].join("\r\n");
  const result = await probePing(
    "example.com",
    {
      platform: "windows",
      count: 4,
      timeoutMs: 1000,
    },
    {
      execFile: (command, args, _options, callback) => {
        assert.equal(command, "ping");
        assert.deepEqual(args, ["-n", "4", "example.com"]);
        callback(null, stdout, "");
      },
      now: () => 100,
    },
  );

  assert.equal(result.status, "ok");
  assert.equal(result.data.transmitted, 4);
  assert.equal(result.data.received, 4);
  assert.equal(result.data.packetLossPercent, 0);
  assert.equal(result.data.averageMs, 18);
});

test("probePing returns error when ping receives no packets", async () => {
  const stdout = [
    "--- example.com ping statistics ---",
    "4 packets transmitted, 0 received, 100% packet loss",
  ].join("\n");
  const result = await probePing(
    "example.com",
    {
      platform: "unix",
      count: 4,
    },
    {
      execFile: createExecFile(stdout, "", { code: 1, message: "failed" }),
      now: () => 100,
    },
  );

  assert.equal(result.status, "error");
  assert.equal(result.error.code, "PING_ERROR");
});

test("probePing returns timeout errors from the command runner", async () => {
  const result = await probePing(
    "example.com",
    {
      platform: "unix",
      count: 4,
      timeoutMs: 20,
    },
    {
      execFile: createExecFile("", "", {
        killed: true,
        message: "command timed out",
      }),
      now: () => 100,
    },
  );

  assert.equal(result.status, "error");
  assert.equal(result.error.code, "TIMEOUT_ERROR");
});
