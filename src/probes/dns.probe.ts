import type { LookupAddress } from "node:dns";
import { lookup, resolve4, resolve6 } from "node:dns/promises";

import { DnsError, toResultError } from "../core/errors.js";
import {
  createErrorResult,
  createOkResult,
  type ProbeResult,
} from "../core/result.js";
import type { DnsProbeData } from "../core/types.js";

//A function that takes a hostname and returns a list of IP addresses asynchronously.
type DnsResolver = (hostname: string) => Promise<string[]>;
type SystemLookupResolver = (
  hostname: string,
  options: { all: true },
) => Promise<LookupAddress[]>;

interface DnsProbeDependencies {
  resolve4?: DnsResolver;
  resolve6?: DnsResolver;
  lookup?: SystemLookupResolver;
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
    lookup: dependencies.lookup ?? lookupAll,
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
        resolver: "direct",
      },
    });
  }

  const fallbackResult = await Promise.allSettled([
    resolvers.lookup(target, { all: true }),
  ]);
  const fallbackAddresses = getLookupAddresses(fallbackResult[0]);
  const fallbackDurationMs = Math.max(0, Math.round(now() - startedAt));
  const details = buildDnsFailureDetails(ipv4Result, ipv6Result);

  if (fallbackAddresses.addresses.length > 0) {
    return createOkResult({
      target,
      durationMs: fallbackDurationMs,
      data: {
        hostname: target,
        ipv4: fallbackAddresses.ipv4,
        ipv6: fallbackAddresses.ipv6,
        addresses: fallbackAddresses.addresses,
        resolver: "system-fallback",
        warning:
          "Direct DNS query failed, but the system resolver worked.",
        directResolverErrors: details,
      },
    });
  }

  addLookupFailureDetails(details, fallbackResult[0]);
  const error = new DnsError(`DNS lookup failed for ${target}`, {
    target,
    details,
  });

  return createErrorResult({
    target,
    durationMs: fallbackDurationMs,
    error: toResultError(error),
  });
}

// Extracts address arrays from fulfilled DNS resolver results.
function getResolvedAddresses(
  result: PromiseSettledResult<string[]>,
): string[] {
  return result.status === "fulfilled" ? result.value : [];
}

// Runs system DNS lookup with all addresses enabled.
async function lookupAll(
  hostname: string,
  options: { all: true },
): Promise<LookupAddress[]> {
  const result = await lookup(hostname, options);

  return Array.isArray(result) ? result : [result];
}

// Groups system resolver addresses by IP family.
function getLookupAddresses(
  result: PromiseSettledResult<LookupAddress[]>,
): Pick<DnsProbeData, "ipv4" | "ipv6" | "addresses"> {
  if (result.status === "rejected") {
    return {
      ipv4: [],
      ipv6: [],
      addresses: [],
    };
  }

  const ipv4 = result.value
    .filter((address) => address.family === 4)
    .map((address) => address.address);
  const ipv6 = result.value
    .filter((address) => address.family === 6)
    .map((address) => address.address);

  return {
    ipv4,
    ipv6,
    addresses: [...ipv4, ...ipv6],
  };
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

// Adds system resolver errors to the DNS failure details.
function addLookupFailureDetails(
  details: Record<string, unknown>,
  lookupResult: PromiseSettledResult<LookupAddress[]>,
): void {
  if (lookupResult.status === "rejected") {
    details.lookupError = getErrorMessage(lookupResult.reason);
  }
}

// Converts unknown DNS resolver errors into readable messages.
function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unknown DNS error";
}
