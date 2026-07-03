import type { Finding, Severity } from "../core/types.js";

export type SecurityHeaderStatus = "OK" | "WARN" | "ERROR";

export interface SecurityHeaderCheck {
  name: string;
  label: string;
  status: SecurityHeaderStatus;
  value: string | null;
  message: string;
}

export interface SecurityHeaderAnalysis {
  checks: SecurityHeaderCheck[];
  findings: Finding[];
}

interface SecurityHeaderRule {
  name: string;
  label: string;
  missingStatus: SecurityHeaderStatus;
  missingSeverity: Severity;
  requiredValue?: string;
}

type HeaderMap = Record<string, string | string[]>;

const SECURITY_HEADER_RULES: SecurityHeaderRule[] = [
  {
    name: "content-security-policy",
    label: "CSP",
    missingStatus: "ERROR",
    missingSeverity: "critical",
  },
  {
    name: "strict-transport-security",
    label: "HSTS",
    missingStatus: "ERROR",
    missingSeverity: "critical",
  },
  {
    name: "x-frame-options",
    label: "X-Frame-Options",
    missingStatus: "WARN",
    missingSeverity: "warning",
  },
  {
    name: "x-content-type-options",
    label: "X-Content-Type-Options",
    missingStatus: "ERROR",
    missingSeverity: "critical",
    requiredValue: "nosniff",
  },
  {
    name: "referrer-policy",
    label: "Referrer-Policy",
    missingStatus: "WARN",
    missingSeverity: "warning",
  },
  {
    name: "permissions-policy",
    label: "Permissions-Policy",
    missingStatus: "WARN",
    missingSeverity: "warning",
  },
];

// Analyzes security headers and classifies each header as OK, WARN, or ERROR.
export function analyzeSecurityHeaders(headers: HeaderMap): SecurityHeaderAnalysis {
  const normalizedHeaders = normalizeHeaders(headers);
  const checks = SECURITY_HEADER_RULES.map((rule) =>
    evaluateSecurityHeader(normalizedHeaders, rule),
  );
  const findings = checks
    .filter((check) => check.status !== "OK")
    .map((check) => buildSecurityFinding(check));

  return {
    checks,
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

// Evaluates a single security header rule against response headers.
function evaluateSecurityHeader(
  headers: HeaderMap,
  rule: SecurityHeaderRule,
): SecurityHeaderCheck {
  const value = getHeaderValue(headers, rule.name);

  if (value === undefined) {
    return {
      name: rule.name,
      label: rule.label,
      status: rule.missingStatus,
      value: null,
      message: `${rule.label} header is missing.`,
    };
  }

  if (
    rule.requiredValue !== undefined &&
    value.toLowerCase() !== rule.requiredValue
  ) {
    return {
      name: rule.name,
      label: rule.label,
      status: "ERROR",
      value,
      message: `${rule.label} header should be ${rule.requiredValue}.`,
    };
  }

  return {
    name: rule.name,
    label: rule.label,
    status: "OK",
    value,
    message: `${rule.label} header is present.`,
  };
}

// Reads the first value for a header as a display string.
function getHeaderValue(headers: HeaderMap, name: string): string | undefined {
  const value = headers[name.toLowerCase()];

  if (Array.isArray(value)) {
    return value[0];
  }

  return value;
}

// Converts a failed security header check into a stable finding.
function buildSecurityFinding(check: SecurityHeaderCheck): Finding {
  return {
    severity: check.status === "ERROR" ? "critical" : "warning",
    code: `SECURITY_HEADER_${check.name.toUpperCase().replaceAll("-", "_")}`,
    message: check.message,
    recommendation: "Configure this security header for stronger browser protections.",
    source: "analyzer",
  };
}
