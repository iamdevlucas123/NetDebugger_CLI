import {
  runExternalCommand,
  type CommandRunnerDependencies,
  type CommandRunnerResult,
} from "./command-runner.js";

export interface CurlAdapterOptions {
  timeoutMs?: number;
  maxRedirects?: number;
}

export interface CurlHeaderBlock {
  statusLine: string;
  statusCode?: number;
  headers: Record<string, string[]>;
}

export interface CurlHeadResult extends CommandRunnerResult {
  command: string;
  args: string[];
  ok: boolean;
  headerBlocks: CurlHeaderBlock[];
}

// Runs curl in HEAD and follow-redirect mode for comparison with native HTTP checks.
export async function runCurlHead(
  url: string,
  options: CurlAdapterOptions = {},
  dependencies: CommandRunnerDependencies = {},
): Promise<CurlHeadResult> {
  const args = buildCurlHeadArgs(url, options);
  const result = await runExternalCommand(
    "curl",
    args,
    { timeoutMs: options.timeoutMs ?? 10000 },
    dependencies,
  );

  return {
    ...result,
    command: "curl",
    args,
    ok: result.exitCode === 0 && !result.timedOut,
    headerBlocks: parseCurlHeaderBlocks(result.stdout),
  };
}

// Builds arguments for curl -I -L without shell interpolation.
export function buildCurlHeadArgs(
  url: string,
  options: CurlAdapterOptions = {},
): string[] {
  const args = ["-I", "-L"];

  if (options.maxRedirects !== undefined) {
    args.push("--max-redirs", String(options.maxRedirects));
  }

  args.push(url);

  return args;
}

// Parses curl header output into one block per response hop.
export function parseCurlHeaderBlocks(output: string): CurlHeaderBlock[] {
  return output
    .split(/\r?\n\r?\n/)
    .map((block) => block.trim())
    .filter((block) => block.length > 0)
    .map((block) => parseCurlHeaderBlock(block));
}

// Parses one curl response header block.
function parseCurlHeaderBlock(block: string): CurlHeaderBlock {
  const [statusLine = "", ...headerLines] = block.split(/\r?\n/);
  const statusCode = parseStatusCode(statusLine);

  return {
    statusLine,
    ...(statusCode !== undefined ? { statusCode } : {}),
    headers: parseHeaderLines(headerLines),
  };
}

// Parses HTTP status code from a curl status line.
function parseStatusCode(statusLine: string): number | undefined {
  const match = /^HTTP\/\S+\s+(\d{3})/.exec(statusLine);

  return match?.[1] !== undefined ? Number(match[1]) : undefined;
}

// Parses header lines into a case-insensitive multivalue map.
function parseHeaderLines(lines: string[]): Record<string, string[]> {
  const headers: Record<string, string[]> = {};

  for (const line of lines) {
    const separatorIndex = line.indexOf(":");

    if (separatorIndex < 0) {
      continue;
    }

    const name = line.slice(0, separatorIndex).trim().toLowerCase();
    const value = line.slice(separatorIndex + 1).trim();
    headers[name] ??= [];
    headers[name].push(value);
  }

  return headers;
}
