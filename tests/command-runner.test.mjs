import assert from "node:assert/strict";
import test from "node:test";

import { runExternalCommand } from "../dist/adapters/command-runner.js";

test("runExternalCommand returns stdout, stderr, and zero exit code", async () => {
  const result = await runExternalCommand(
    "tool",
    ["--flag"],
    { timeoutMs: 1234 },
    {
      execFile: (file, args, options, callback) => {
        assert.equal(file, "tool");
        assert.deepEqual(args, ["--flag"]);
        assert.equal(options.timeout, 1234);
        assert.equal(options.windowsHide, true);
        assert.equal(options.encoding, "utf8");
        callback(null, "ok", "");
      },
    },
  );

  assert.deepEqual(result, {
    stdout: "ok",
    stderr: "",
    exitCode: 0,
    timedOut: false,
  });
});

test("runExternalCommand returns non-zero command errors as serializable data", async () => {
  const result = await runExternalCommand(
    "tool",
    [],
    {},
    {
      execFile: (_file, _args, _options, callback) => {
        callback({ code: 2, message: "failed" }, "", "bad input");
      },
    },
  );

  assert.deepEqual(result, {
    stdout: "",
    stderr: "bad input",
    exitCode: 2,
    timedOut: false,
    errorMessage: "failed",
  });
});

test("runExternalCommand marks killed processes as timed out", async () => {
  const result = await runExternalCommand(
    "tool",
    [],
    {},
    {
      execFile: (_file, _args, _options, callback) => {
        callback({ killed: true, message: "timeout" }, "", "");
      },
    },
  );

  assert.equal(result.timedOut, true);
  assert.equal(result.errorMessage, "timeout");
});
