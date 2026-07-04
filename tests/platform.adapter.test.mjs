import assert from "node:assert/strict";
import test from "node:test";

import {
  buildPingCommand,
  buildTracerouteCommand,
  detectRuntimePlatform,
} from "../dist/adapters/platform.adapter.js";

test("detectRuntimePlatform maps Node platforms to command families", () => {
  assert.equal(detectRuntimePlatform("win32"), "windows");
  assert.equal(detectRuntimePlatform("linux"), "unix");
  assert.equal(detectRuntimePlatform("darwin"), "unix");
});

test("buildPingCommand returns platform-specific ping arguments", () => {
  assert.deepEqual(buildPingCommand("example.com", 4, "windows"), {
    command: "ping",
    args: ["-n", "4", "example.com"],
  });
  assert.deepEqual(buildPingCommand("example.com", 4, "unix"), {
    command: "ping",
    args: ["-c", "4", "example.com"],
  });
});

test("buildTracerouteCommand returns platform-specific trace commands", () => {
  assert.deepEqual(buildTracerouteCommand("example.com", "windows"), {
    command: "tracert",
    args: ["example.com"],
  });
  assert.deepEqual(buildTracerouteCommand("example.com", "unix"), {
    command: "traceroute",
    args: ["example.com"],
  });
});
