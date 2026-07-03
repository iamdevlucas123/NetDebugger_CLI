import { request as requestHttp } from "node:http";
import { request as requestHttps } from "node:https";
import type { IncomingMessage, RequestOptions } from "node:http";

import {
  DnsError,
  HttpRequestError,
  TimeoutError,
  TlsHandshakeError,
  toResultError,
} from "../core/errors.js";
import {
  createErrorResult,
  createOkResult,
  type ProbeResult,
} from "../core/result.js";
import type { HttpProbeData, HttpRedirect } from "../core/types.js";

interface HttpProbeOptions {
  timeoutMs?: number;
  maxRedirects?: number;
  method?: "GET" | "HEAD";
}

interface HttpProbeDependencies {
  now?: () => number;
}

interface HttpResponseData {
  statusCode: number;
  statusText?: string;
  headers: Record<string, string | string[]>;
}

// Performs an HTTP/HTTPS request, follows redirects, and returns the standard probe result.
export async function probeHttp(
  input: string,
  options: HttpProbeOptions = {},
  dependencies: HttpProbeDependencies = {},
): Promise<ProbeResult<HttpProbeData>> {
  const timeoutMs = options.timeoutMs ?? 5000;
  const maxRedirects = options.maxRedirects ?? 5;
  const method = options.method ?? "GET";
  const now = dependencies.now ?? Date.now;
  const startedAt = now();

  try {
    const initialUrl = parseHttpUrl(input);
    const { response, finalUrl, redirects } = await requestWithRedirects(
      initialUrl,
      {
        method,
        timeoutMs,
        maxRedirects,
      },
    );
    const totalMs = Math.max(0, Math.round(now() - startedAt));

    return createOkResult({
      target: initialUrl.href,
      durationMs: totalMs,
      data: {
        url: initialUrl.href,
        finalUrl: finalUrl.href,
        method,
        statusCode: response.statusCode,
        ...(response.statusText !== undefined
          ? { statusText: response.statusText }
          : {}),
        headers: response.headers,
        redirects,
        timing: {
          startAt: new Date(startedAt).toISOString(),
          totalMs,
        },
      },
    });
  } catch (error) {
    const durationMs = Math.max(0, Math.round(now() - startedAt));
    const normalizedError = normalizeHttpError(error, input, timeoutMs);

    return createErrorResult({
      target: input,
      durationMs,
      error: toResultError(normalizedError),
    });
  }
}

// Parses and validates user input as an HTTP or HTTPS URL.
function parseHttpUrl(input: string): URL {
  const url = new URL(input);

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new HttpRequestError("Only http and https URLs are supported.", {
      target: input,
      details: {
        protocol: url.protocol,
      },
    });
  }

  return url;
}

// Requests a URL and follows redirects up to the configured limit.
async function requestWithRedirects(
  initialUrl: URL,
  options: Required<Pick<HttpProbeOptions, "timeoutMs" | "maxRedirects" | "method">>,
): Promise<{
  response: HttpResponseData;
  finalUrl: URL;
  redirects: HttpRedirect[];
}> {
  let currentUrl = initialUrl;
  const redirects: HttpRedirect[] = [];

  for (let redirectCount = 0; redirectCount <= options.maxRedirects; redirectCount++) {
    const response = await requestOnce(currentUrl, options);
    const location = getRedirectLocation(response);

    if (location === undefined) {
      return {
        response,
        finalUrl: currentUrl,
        redirects,
      };
    }

    if (redirectCount === options.maxRedirects) {
      throw new HttpRequestError("Too many HTTP redirects.", {
        target: initialUrl.href,
        details: {
          maxRedirects: options.maxRedirects,
        },
      });
    }

    redirects.push({
      statusCode: response.statusCode,
      location,
    });
    currentUrl = new URL(location, currentUrl);
  }

  throw new HttpRequestError("HTTP redirect handling failed.", {
    target: initialUrl.href,
  });
}

// Performs a single HTTP/HTTPS request without following redirects.
function requestOnce(
  url: URL,
  options: Required<Pick<HttpProbeOptions, "timeoutMs" | "method">>,
): Promise<HttpResponseData> {
  return new Promise((resolve, reject) => {
    const requestOptions: RequestOptions = {
      method: options.method,
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port,
      path: `${url.pathname}${url.search}`,
    };
    const requestFn = url.protocol === "https:" ? requestHttps : requestHttp;
    const request = requestFn(requestOptions, (response: IncomingMessage) => {
      response.resume();
      response.once("end", () => {
        resolve({
          statusCode: response.statusCode ?? 0,
          ...(response.statusMessage !== undefined
            ? { statusText: response.statusMessage }
            : {}),
          headers: normalizeHeaders(response.headers),
        });
      });
    });

    request.setTimeout(options.timeoutMs, () => {
      request.destroy(
        new TimeoutError(`HTTP request timed out for ${url.href}`, {
          target: url.href,
          details: {
            operation: "http.request",
            timeoutMs: options.timeoutMs,
          },
        }),
      );
    });

    request.once("error", reject);
    request.end();
  });
}

// Extracts redirect target from redirect responses.
function getRedirectLocation(response: HttpResponseData): string | undefined {
  if (response.statusCode < 300 || response.statusCode > 399) {
    return undefined;
  }

  const location = response.headers.location;

  if (Array.isArray(location)) {
    return location[0];
  }

  return location;
}

// Converts Node headers into the project's string or string array shape.
function normalizeHeaders(
  headers: IncomingMessage["headers"],
): Record<string, string | string[]> {
  const normalized: Record<string, string | string[]> = {};

  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) {
      continue;
    }

    normalized[key.toLowerCase()] = value;
  }

  return normalized;
}

// Maps native network errors to NetDebugger domain errors.
function normalizeHttpError(
  error: unknown,
  target: string,
  timeoutMs: number,
): Error {
  if (
    error instanceof DnsError ||
    error instanceof HttpRequestError ||
    error instanceof TimeoutError ||
    error instanceof TlsHandshakeError
  ) {
    return error;
  }

  if (error instanceof Error && error.name === "TimeoutError") {
    return error;
  }

  const code = getErrorCode(error);

  if (code === "ENOTFOUND" || code === "EAI_AGAIN") {
    return new DnsError(`DNS lookup failed for ${target}`, {
      target,
      cause: error,
      details: { code },
    });
  }

  if (isTlsErrorCode(code)) {
    return new TlsHandshakeError(`TLS handshake failed for ${target}`, {
      target,
      cause: error,
      details: { code },
    });
  }

  if (error instanceof TimeoutError) {
    return error;
  }

  if (error instanceof Error && error.message.includes("timed out")) {
    return new TimeoutError(`HTTP request timed out for ${target}`, {
      target,
      cause: error,
      details: {
        timeoutMs,
      },
    });
  }

  return new HttpRequestError(`HTTP request failed for ${target}`, {
    target,
    cause: error,
    ...(code !== undefined ? { details: { code } } : {}),
  });
}

// Extracts a stable error code from unknown Node errors.
function getErrorCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("code" in error)) {
    return undefined;
  }

  const code = (error as { code?: unknown }).code;

  return typeof code === "string" ? code : undefined;
}

// Detects Node TLS-related error codes.
function isTlsErrorCode(code: string | undefined): boolean {
  return (
    code !== undefined &&
    (code.startsWith("ERR_TLS") ||
      code.startsWith("CERT_") ||
      code === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
      code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE")
  );
}
