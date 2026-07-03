import type { Finding } from "../core/types.js";

export interface HeaderInfo {
  name: string;
  value: string;
}

export interface CookieIssue {
  cookie: string;
  missing: Array<"HttpOnly" | "Secure" | "SameSite">;
}

export interface HeaderAnalysis {
  headers: HeaderInfo[];
  cookieIssues: CookieIssue[];
  findings: Finding[];
}

type HeaderMap = Record<string, string | string[]>;

const COMMON_HEADERS = [
  "content-type",
  "cache-control",
  "set-cookie",
  "server",
  "location",
] as const;

// Analyzes common HTTP headers and returns useful findings.
export function analyzeHeaders(headers: HeaderMap): HeaderAnalysis {
  const normalizedHeaders = normalizeHeaders(headers);
  const headerInfo = COMMON_HEADERS.map((name) => ({
    name,
    value: getHeaderValue(normalizedHeaders, name) ?? "missing",
  }));
  const cookieIssues = analyzeSetCookieHeaders(
    getHeaderValues(normalizedHeaders, "set-cookie"),
  );
  const findings = [
    ...buildCookieFindings(cookieIssues),
    ...buildCacheFindings(getHeaderValue(normalizedHeaders, "cache-control")),
    ...buildServerFindings(getHeaderValue(normalizedHeaders, "server")),
  ];

  return {
    headers: headerInfo,
    cookieIssues,
    findings,
  };
}

// Converts header keys to lowercase so lookup is case-insensitive.
function normalizeHeaders(headers: HeaderMap): HeaderMap {
  const normalizedHeaders: HeaderMap = {};

  for (const [key, value] of Object.entries(headers)) {
    normalizedHeaders[key.toLowerCase()] = value;
  }

  return normalizedHeaders;
}

// Reads the first value for a header as a display string.
function getHeaderValue(headers: HeaderMap, name: string): string | undefined {
  const value = headers[name.toLowerCase()];

  if (Array.isArray(value)) {
    return value[0];
  }

  return value;
}

// Reads all values for a header as strings.
function getHeaderValues(headers: HeaderMap, name: string): string[] {
  const value = headers[name.toLowerCase()];

  if (Array.isArray(value)) {
    return value;
  }

  return value !== undefined ? [value] : [];
}

// Detects missing cookie security attributes.
function analyzeSetCookieHeaders(cookies: string[]): CookieIssue[] {
  return cookies
    .map((cookie) => {
      const lowerCookie = cookie.toLowerCase();
      const missing: CookieIssue["missing"] = [];

      if (!lowerCookie.includes("httponly")) {
        missing.push("HttpOnly");
      }

      if (!lowerCookie.includes("secure")) {
        missing.push("Secure");
      }

      if (!lowerCookie.includes("samesite=")) {
        missing.push("SameSite");
      }

      return {
        cookie,
        missing,
      };
    })
    .filter((issue) => issue.missing.length > 0);
}

// Builds findings for cookies missing security attributes.
function buildCookieFindings(cookieIssues: CookieIssue[]): Finding[] {
  return cookieIssues.map((issue) => ({
    severity: "warning",
    code: "COOKIE_SECURITY_ATTRIBUTES_MISSING",
    message: `Cookie is missing ${issue.missing.join(", ")} attribute(s).`,
    recommendation: "Set HttpOnly, Secure, and SameSite for session cookies.",
    source: "analyzer",
  }));
}

// Builds findings for cache headers that may expose sensitive data.
function buildCacheFindings(cacheControl: string | undefined): Finding[] {
  if (cacheControl === undefined) {
    return [
      {
        severity: "warning",
        code: "CACHE_CONTROL_MISSING",
        message: "Cache-Control header is missing.",
        recommendation: "Set an explicit Cache-Control policy.",
        source: "analyzer",
      },
    ];
  }

  const lowerCacheControl = cacheControl.toLowerCase();

  if (
    lowerCacheControl.includes("no-store") ||
    lowerCacheControl.includes("private")
  ) {
    return [];
  }

  return [
    {
      severity: "warning",
      code: "CACHE_CONTROL_WEAK",
      message: "Cache-Control header may allow unintended caching.",
      recommendation: "Use no-store or private for sensitive responses.",
      source: "analyzer",
    },
  ];
}

// Builds findings when the server implementation is exposed.
function buildServerFindings(server: string | undefined): Finding[] {
  if (server === undefined) {
    return [];
  }

  return [
    {
      severity: "info",
      code: "SERVER_HEADER_EXPOSED",
      message: `Server header is exposed as ${server}.`,
      recommendation: "Consider removing or minimizing the Server header.",
      source: "analyzer",
    },
  ];
}
