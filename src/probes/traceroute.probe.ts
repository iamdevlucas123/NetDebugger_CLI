import {
  buildTracerouteCommand,
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

export interface TracerouteProbeOptions {
  timeoutMs?: number;
  platform?: RuntimePlatform;
}

export interface TracerouteHop {
  hop: number;
  output: string;
}

export interface TracerouteProbeData {
  host: string;
  command: string;
  args: string[];
  hops: TracerouteHop[];
  stdout: string;
  completed: boolean;
  stderr?: string;
}

export interface TracerouteProbeDependencies extends CommandRunnerDependencies {
  now?: () => number;
}

// Executes traceroute or tracert and returns hop output in the standard envelope.
export async function probeTraceroute(
  host: string,
  options: TracerouteProbeOptions = {},
  dependencies: TracerouteProbeDependencies = {},
): Promise<ProbeResult<TracerouteProbeData>> {
  const target = host.trim();
  const now = dependencies.now ?? Date.now;
  const startedAt = now();
  const platform = options.platform ?? detectRuntimePlatform();
  const command = buildTracerouteCommand(target, platform);
  const result = await runExternalCommand(
    command.command,
    command.args,
    { timeoutMs: options.timeoutMs ?? 30000 },
    dependencies,
  );
  const durationMs = Math.max(0, Math.round(now() - startedAt));

  if (result.timedOut) {
    const error = new TimeoutError(`Traceroute timed out for ${target}`, {
      target,
      details: {
        operation: "traceroute",
        timeoutMs: options.timeoutMs ?? 30000,
      },
    });

    return createErrorResult({
      target,
      durationMs,
      error: toResultError(error),
    });
  }

  if (result.exitCode !== 0) {
    return createErrorResult({
      target,
      durationMs,
      error: {
        code: "TRACEROUTE_ERROR",
        message: `Traceroute failed for ${target}`,
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
    data: {
      host: target,
      command: command.command,
      args: command.args,
      hops: parseTracerouteHops(result.stdout),
      stdout: result.stdout,
      completed: true,
      ...(result.stderr.length > 0 ? { stderr: result.stderr } : {}),
    },
  });
}

// Parses numbered traceroute or tracert hop lines.
function parseTracerouteHops(output: string): TracerouteHop[] {
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .map((line) => parseHopLine(line))
    .filter((hop): hop is TracerouteHop => hop !== null);
}

// Converts a single numbered hop line into structured hop data.
function parseHopLine(line: string): TracerouteHop | null {
  const match = /^(\d+)\s+(.+)$/.exec(line);

  if (match === null) {
    return null;
  }

  return {
    hop: Number(match[1]),
    output: match[2] ?? "",
  };
}
