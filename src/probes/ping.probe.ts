import {
  buildPingCommand,
  detectRuntimePlatform,
  type RuntimePlatform,
} from "../adapters/platform.adapter.js";
import {
  runExternalCommand,
  type CommandRunnerDependencies,
} from "../adapters/command-runner.js";
import { TimeoutError, toResultError } from "../core/errors.js";
import {
  createErrorResult,
  createOkResult,
  type ProbeResult,
} from "../core/result.js";

export interface PingProbeOptions {
  count?: number;
  timeoutMs?: number;
  platform?: RuntimePlatform;
}

export interface PingProbeData {
  host: string;
  command: string;
  args: string[];
  transmitted: number;
  received: number;
  packetLossPercent: number;
  reachable: boolean;
  stdout: string;
  averageMs?: number;
  stderr?: string;
}

export interface PingProbeDependencies extends CommandRunnerDependencies {
  now?: () => number;
}

interface ParsedPingOutput {
  transmitted: number;
  received: number;
  packetLossPercent: number;
  averageMs?: number;
}

// Executes the platform ping command and returns packet loss and latency facts.
export async function probePing(
  host: string,
  options: PingProbeOptions = {},
  dependencies: PingProbeDependencies = {},
): Promise<ProbeResult<PingProbeData>> {
  const target = host.trim();
  const now = dependencies.now ?? Date.now;
  const startedAt = now();
  const count = options.count ?? 4;
  const platform = options.platform ?? detectRuntimePlatform();
  const command = buildPingCommand(target, count, platform);
  const result = await runExternalCommand(
    command.command,
    command.args,
    { timeoutMs: options.timeoutMs ?? 10000 },
    dependencies,
  );
  const durationMs = Math.max(0, Math.round(now() - startedAt));

  if (result.timedOut) {
    const error = new TimeoutError(`Ping timed out for ${target}`, {
      target,
      details: {
        operation: "ping",
        timeoutMs: options.timeoutMs ?? 10000,
      },
    });

    return createErrorResult({
      target,
      durationMs,
      error: toResultError(error),
    });
  }

  const parsed = parsePingOutput(result.stdout, platform);

  if (result.exitCode !== 0 || parsed.received === 0) {
    return createErrorResult({
      target,
      durationMs,
      error: {
        code: "PING_ERROR",
        message: `Ping failed for ${target}`,
        details: {
          command: command.command,
          args: command.args,
          exitCode: result.exitCode,
          stdout: result.stdout,
          stderr: result.stderr,
          ...(result.errorMessage !== undefined
            ? { errorMessage: result.errorMessage }
            : {}),
        },
      },
    });
  }

  return createOkResult({
    target,
    durationMs,
    data: buildPingData(target, command, result.stdout, result.stderr, parsed),
  });
}

// Builds serializable ping probe data from parsed command output.
function buildPingData(
  host: string,
  command: { command: string; args: string[] },
  stdout: string,
  stderr: string,
  parsed: ParsedPingOutput,
): PingProbeData {
  return {
    host,
    command: command.command,
    args: command.args,
    transmitted: parsed.transmitted,
    received: parsed.received,
    packetLossPercent: parsed.packetLossPercent,
    reachable: parsed.received > 0,
    stdout,
    ...(parsed.averageMs !== undefined ? { averageMs: parsed.averageMs } : {}),
    ...(stderr.length > 0 ? { stderr } : {}),
  };
}

// Parses ping output from Windows or Unix-like systems.
function parsePingOutput(
  output: string,
  platform: RuntimePlatform,
): ParsedPingOutput {
  return platform === "windows"
    ? parseWindowsPingOutput(output)
    : parseUnixPingOutput(output);
}

// Parses Windows ping packet and average latency output.
function parseWindowsPingOutput(output: string): ParsedPingOutput {
  const packetMatch = /Packets:\s*Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*(\d+)/i.exec(
    output,
  );
  const averageMatch = /Average\s*=\s*(\d+(?:\.\d+)?)ms/i.exec(output);
  const transmitted = readNumber(packetMatch?.[1]);
  const received = readNumber(packetMatch?.[2]);
  const lost = readNumber(packetMatch?.[3]);
  const packetLossPercent =
    transmitted > 0 ? Math.round((lost / transmitted) * 100) : 100;

  return {
    transmitted,
    received,
    packetLossPercent,
    ...(averageMatch?.[1] !== undefined
      ? { averageMs: Number(averageMatch[1]) }
      : {}),
  };
}

// Parses Unix ping packet and average latency output.
function parseUnixPingOutput(output: string): ParsedPingOutput {
  const packetMatch = /(\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets\s+)?received/i.exec(
    output,
  );
  const lossMatch = /(\d+(?:\.\d+)?)%\s*packet loss/i.exec(output);
  const averageMatch = /(?:rtt|round-trip).*=\s*[\d.]+\/([\d.]+)\//i.exec(
    output,
  );

  return {
    transmitted: readNumber(packetMatch?.[1]),
    received: readNumber(packetMatch?.[2]),
    packetLossPercent:
      lossMatch?.[1] !== undefined ? Number(lossMatch[1]) : 100,
    ...(averageMatch?.[1] !== undefined
      ? { averageMs: Number(averageMatch[1]) }
      : {}),
  };
}

// Converts optional regex captures into numbers.
function readNumber(value: string | undefined): number {
  return value !== undefined ? Number(value) : 0;
}
