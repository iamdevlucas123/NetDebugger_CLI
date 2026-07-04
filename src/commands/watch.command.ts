import { appendFile } from "node:fs/promises";
import type { Command } from "commander";

import { InvalidUrlError } from "../core/errors.js";
import {
  buildDoctorJsonPayload,
  type DoctorJsonPayload,
} from "../output/json.reporter.js";
import { runDoctor, type DoctorReport } from "../services/doctor.service.js";

interface WatchCommandOptions {
  interval: string;
  timeout: string;
  runs: string;
  output?: string;
}

export interface WatchSnapshot {
  target: string;
  status: DoctorJsonPayload["status"];
  statusCode?: number;
  durationMs: number;
  timestamp: string;
  changed: boolean;
  previousStatusKey?: string;
  statusKey: string;
  score: number;
  mainIssue: string;
}

// Registers the watch command and repeatedly runs doctor for one URL.
export function registerWatchCommand(program: Command): void {
  program
    .command("watch <url>")
    .description("Run doctor repeatedly and print status changes over time")
    .option("--interval <seconds>", "Interval between doctor runs in seconds", "30")
    .option("--timeout <ms>", "Per-step timeout in milliseconds", "5000")
    .option("--runs <count>", "Number of HTTP samples per doctor run", "1")
    .option("--output <file>", "Append JSON snapshots to a file")
    .action(async (url: string, options: WatchCommandOptions) => {
      const intervalSeconds = parsePositiveInteger(options.interval, "interval");
      const timeoutMs = parsePositiveInteger(options.timeout, "timeout");
      const runs = parsePositiveInteger(options.runs, "runs");

      if (intervalSeconds === null || timeoutMs === null || runs === null) {
        process.exitCode = 2;
        return;
      }

      try {
        const runtimeOptions: WatchRuntimeOptions = {
          intervalMs: intervalSeconds * 1000,
          timeoutMs,
          runs,
        };

        if (options.output !== undefined) {
          runtimeOptions.outputPath = options.output;
        }

        await runWatchCommand(url, runtimeOptions);
      } catch (error) {
        renderWatchError(error);
        process.exitCode = error instanceof InvalidUrlError ? 2 : 3;
      }
    });
}

interface WatchRuntimeOptions {
  intervalMs: number;
  timeoutMs: number;
  runs: number;
  outputPath?: string;
}

// Runs the long-lived watch loop until the process receives SIGINT.
async function runWatchCommand(
  url: string,
  options: WatchRuntimeOptions,
): Promise<void> {
  let previousStatusKey: string | undefined;
  let running = false;

  const runIteration = async (): Promise<void> => {
    if (running) {
      return;
    }

    running = true;

    try {
      const report = await runDoctor(url, {
        timeoutMs: options.timeoutMs,
        runs: options.runs,
      });
      const snapshot = buildWatchSnapshot(report, previousStatusKey);

      console.log(formatWatchLine(snapshot));
      await writeWatchSnapshot(snapshot, options.outputPath);
      previousStatusKey = snapshot.statusKey;
    } finally {
      running = false;
    }
  };

  await runIteration();

  await new Promise<void>((resolve) => {
    const timer = setInterval(() => {
      void runIteration();
    }, options.intervalMs);

    process.once("SIGINT", () => {
      clearInterval(timer);
      console.log("\nWatch stopped.");
      resolve();
    });
  });
}

// Builds one serializable watch snapshot from a doctor report.
export function buildWatchSnapshot(
  report: DoctorReport,
  previousStatusKey?: string,
  now: Date = new Date(),
): WatchSnapshot {
  const payload = buildDoctorJsonPayload(report);
  const statusCode = getStatusCode(report);
  const statusKey = `${payload.status}:${statusCode ?? "none"}`;
  const snapshot: WatchSnapshot = {
    target: payload.target,
    status: payload.status,
    durationMs: getDurationMs(report),
    timestamp: now.toISOString(),
    changed: previousStatusKey !== undefined && previousStatusKey !== statusKey,
    statusKey,
    score: payload.score,
    mainIssue: payload.mainIssue,
  };

  if (statusCode !== undefined) {
    snapshot.statusCode = statusCode;
  }

  if (previousStatusKey !== undefined) {
    snapshot.previousStatusKey = previousStatusKey;
  }

  return snapshot;
}

// Formats one watch snapshot for terminal output.
export function formatWatchLine(snapshot: WatchSnapshot): string {
  return [
    `[${formatTime(snapshot.timestamp)}]`,
    snapshot.status.toUpperCase(),
    formatStatusCode(snapshot.statusCode),
    `${snapshot.durationMs}ms`,
    snapshot.changed ? "(changed)" : "",
  ]
    .filter((part) => part.length > 0)
    .join(" ");
}

// Writes one snapshot as JSONL when an output file is configured.
async function writeWatchSnapshot(
  snapshot: WatchSnapshot,
  outputPath: string | undefined,
): Promise<void> {
  if (outputPath === undefined) {
    return;
  }

  await appendFile(outputPath, `${JSON.stringify(snapshot)}\n`, "utf8");
}

// Reads the current HTTP status code from a doctor report.
function getStatusCode(report: DoctorReport): number | undefined {
  const http = report.result.probes.http;

  return http?.status === "ok" ? http.data.statusCode : undefined;
}

// Reads the most relevant duration from a doctor report.
function getDurationMs(report: DoctorReport): number {
  const http = report.result.probes.http;

  return http?.durationMs ?? report.result.durationMs;
}

// Formats ISO timestamps as HH:mm:ss.
function formatTime(timestamp: string): string {
  return new Date(timestamp).toISOString().slice(11, 19);
}

// Formats optional status code for terminal output.
function formatStatusCode(statusCode: number | undefined): string {
  return statusCode !== undefined ? String(statusCode) : "none";
}

// Parses a positive integer CLI option.
function parsePositiveInteger(value: string, label: string): number | null {
  const parsed = Number(value);

  if (!Number.isInteger(parsed) || parsed < 1) {
    console.error(`Invalid ${label}. Use a positive integer.`);
    return null;
  }

  return parsed;
}

// Prints watch command failures that happen before the loop can continue.
function renderWatchError(error: unknown): void {
  if (error instanceof Error) {
    console.error(`Watch error: ${error.message}`);
    return;
  }

  console.error("Watch error: Unexpected failure.");
}
