import type { Finding, TlsProbeData } from "../core/types.js";

export interface TlsAnalysis {
  daysLeft: number | null;
  expired: boolean;
  expiringSoon: boolean;
  findings: Finding[];
}

interface TlsAnalysisOptions {
  now?: Date;
  expiringSoonDays?: number;
}

// Analyzes TLS certificate validity and returns expiration findings.
export function analyzeTlsCertificate(
  data: TlsProbeData,
  options: TlsAnalysisOptions = {},
): TlsAnalysis {
  const now = options.now ?? new Date();
  const expiringSoonDays = options.expiringSoonDays ?? 30;
  const validTo = data.certificate?.validTo;

  if (validTo === undefined) {
    return {
      daysLeft: null,
      expired: false,
      expiringSoon: false,
      findings: [],
    };
  }

  const expiresAt = new Date(validTo);

  if (Number.isNaN(expiresAt.getTime())) {
    return {
      daysLeft: null,
      expired: false,
      expiringSoon: false,
      findings: [
        {
          severity: "warning",
          code: "TLS_CERTIFICATE_DATE_INVALID",
          message: "TLS certificate expiration date could not be parsed.",
          source: "analyzer",
        },
      ],
    };
  }

  const daysLeft = Math.ceil(
    (expiresAt.getTime() - now.getTime()) / 86_400_000,
  );
  const expired = daysLeft < 0;
  const expiringSoon = !expired && daysLeft <= expiringSoonDays;
  const findings = buildTlsFindings(daysLeft, expired, expiringSoon);

  return {
    daysLeft,
    expired,
    expiringSoon,
    findings,
  };
}

// Builds user-facing findings from certificate expiration state.
function buildTlsFindings(
  daysLeft: number,
  expired: boolean,
  expiringSoon: boolean,
): Finding[] {
  if (expired) {
    return [
      {
        severity: "critical",
        code: "TLS_CERTIFICATE_EXPIRED",
        message: `TLS certificate expired ${Math.abs(daysLeft)} day(s) ago.`,
        recommendation: "Renew the TLS certificate.",
        source: "analyzer",
      },
    ];
  }

  if (expiringSoon) {
    return [
      {
        severity: "warning",
        code: "TLS_CERTIFICATE_EXPIRING_SOON",
        message: `TLS certificate expires in ${daysLeft} day(s).`,
        recommendation: "Plan certificate renewal before it expires.",
        source: "analyzer",
      },
    ];
  }

  return [];
}
