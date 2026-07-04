import { execFile, type ExecFileException } from "node:child_process";

export interface CommandRunnerOptions {
  timeoutMs?: number;
}

export interface CommandRunnerResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  timedOut: boolean;
  errorMessage?: string;
}

export type ExecFileDependency = (
  file: string,
  args: string[],
  options: {
    timeout: number;
    windowsHide: true;
    encoding: "utf8";
  },
  callback: (
    error: ExecFileException | null,
    stdout: string | Buffer,
    stderr: string | Buffer,
  ) => void,
) => unknown;

export interface CommandRunnerDependencies {
  execFile?: ExecFileDependency;
}

// Runs a native command with a timeout and returns serializable process output.
export function runExternalCommand(
  command: string,
  args: string[],
  options: CommandRunnerOptions = {},
  dependencies: CommandRunnerDependencies = {},
): Promise<CommandRunnerResult> {
  const timeoutMs = options.timeoutMs ?? 10000;
  const executeFile = dependencies.execFile ?? (execFile as ExecFileDependency);

  return new Promise((resolve) => {
    executeFile(
      command,
      args,
      {
        timeout: timeoutMs,
        windowsHide: true,
        encoding: "utf8",
      },
      (error, stdout, stderr) => {
        resolve({
          stdout: bufferToString(stdout),
          stderr: bufferToString(stderr),
          exitCode: getExitCode(error),
          timedOut: isTimedOut(error),
          ...(error?.message !== undefined ? { errorMessage: error.message } : {}),
        });
      },
    );
  });
}

// Converts child_process output into strings regardless of runtime type.
function bufferToString(value: string | Buffer): string {
  return typeof value === "string" ? value : value.toString("utf8");
}

// Reads the numeric process exit code from an execFile error.
function getExitCode(error: ExecFileException | null): number | null {
  if (error === null) {
    return 0;
  }

  return typeof error.code === "number" ? error.code : null;
}

// Checks whether execFile ended because the timeout killed the process.
function isTimedOut(error: ExecFileException | null): boolean {
  return error?.killed === true;
}
