import { resolve4, resolve6 } from "node:dns/promises";

import { DnsError, toResultError } from "../core/errors.js";
import {
  createErrorResult,
  createOkResult,
  type ProbeResult,
} from "../core/result.js";
import type { DnsProbeData } from "../core/types.js";

//A function that takes a hostname and returns a list of IP addresses asynchronously.
type DnsResolver = (hostname: string) => Promise<string[]>;

interface DnsProbeDependencies {
  resolve4?: DnsResolver;
  resolve6?: DnsResolver;
  now?: () => number;
}

// Resolves a domain to IPv4 and IPv6 addresses and returns the standard probe result.
export async function resolveDns(
  domain: string,
  dependencies: DnsProbeDependencies = {},
): Promise<ProbeResult<DnsProbeData>> {
  const target = domain.trim();
  const now = dependencies.now ?? Date.now;
  const startedAt = now();

  const resolvers = {
    resolve4: dependencies.resolve4 ?? resolve4,
    resolve6: dependencies.resolve6 ?? resolve6,
  };

  const [ipv4Result, ipv6Result] = await Promise.allSettled([
    resolvers.resolve4(target),
    resolvers.resolve6(target),
  ]);

  const durationMs = Math.max(0, Math.round(now() - startedAt));
  const ipv4 = getResolvedAddresses(ipv4Result);
  const ipv6 = getResolvedAddresses(ipv6Result);
  const addresses = [...ipv4, ...ipv6];

  if (addresses.length > 0) {
    return createOkResult({
      target,
      durationMs,
      data: {
        hostname: target,
        ipv4,
        ipv6,
        addresses,
      },
    });
  }

  const details = buildDnsFailureDetails(ipv4Result, ipv6Result);
  const error = new DnsError(`DNS lookup failed for ${target}`, {
    target,
    details,
  });

  return createErrorResult({
    target,
    durationMs,
    error: toResultError(error),
  });
}

// Extracts address arrays from fulfilled DNS resolver results.
function getResolvedAddresses(
  result: PromiseSettledResult<string[]>,
): string[] {
  return result.status === "fulfilled" ? result.value : [];
}

// Builds serializable details for failed IPv4 and IPv6 DNS lookups.
function buildDnsFailureDetails(
  ipv4Result: PromiseSettledResult<string[]>,
  ipv6Result: PromiseSettledResult<string[]>,
): Record<string, unknown> {
  const details: Record<string, unknown> = {};

  if (ipv4Result.status === "rejected") {
    details.ipv4Error = getErrorMessage(ipv4Result.reason);
  }

  if (ipv6Result.status === "rejected") {
    details.ipv6Error = getErrorMessage(ipv6Result.reason);
  }

  return details;
}

// Converts unknown DNS resolver errors into readable messages.
function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unknown DNS error";
}
