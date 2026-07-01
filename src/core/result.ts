export type ResultStatus = "ok" | "error";

export interface ResultError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface OkResult<TData> {
  status: "ok";
  target: string;
  durationMs: number;
  data: TData;
  error: null;
}

export interface ErrorResult {
  status: "error";
  target: string;
  durationMs: number;
  data: null;
  error: ResultError;
}

export type ProbeResult<TData> = OkResult<TData> | ErrorResult;

export function createOkResult<TData>(input: {
  target: string;
  durationMs: number;
  data: TData;
}): OkResult<TData> {
  return {
    status: "ok",
    target: input.target,
    durationMs: input.durationMs,
    data: input.data,
    error: null,
  };
}

export function createErrorResult(input: {
  target: string;
  durationMs: number;
  error: ResultError;
}): ErrorResult {
  return {
    status: "error",
    target: input.target,
    durationMs: input.durationMs,
    data: null,
    error: input.error,
  };
}

export function isOkResult<TData>(
  result: ProbeResult<TData>,
): result is OkResult<TData> {
  return result.status === "ok";
}

export function isErrorResult<TData>(
  result: ProbeResult<TData>,
): result is ErrorResult {
  return result.status === "error";
}
