//This allows write node commands on Terminal
import type { Command } from "commander";

import { resolveDns } from "../probes/dns.probe.js";
import type { DnsProbeData, ProbeResult } from "../core/types.js";

// Registers the dns command and connects CLI input to the DNS probe.
export function registerDnsCommand(program: Command): void {
  program
    .command("dns <domain>")
    .description("Resolve IPv4 and IPv6 records for a domain")
    .action(async (domain: string) => {
      const result = await resolveDns(domain);

      renderDnsResult(result);

      if (result.status === "error") {
        process.exitCode = 1;
      }
    });
}

// Prints the DNS probe result in a compact human-readable format.
function renderDnsResult(result: ProbeResult<DnsProbeData>): void {
  console.log(`Domain: ${result.target}`);

  if (result.status === "ok") {
    console.log(`IPv4: ${formatAddresses(result.data.ipv4)}`);
    console.log(`IPv6: ${formatAddresses(result.data.ipv6)}`);
    console.log(`DNS lookup: ${result.durationMs}ms`);
    console.log(`Resolver: ${formatResolver(result.data.resolver)}`);
    console.log("Status: OK");

    if (result.data.warning !== undefined) {
      console.log(`Warning: ${result.data.warning}`);
    }

    return;
  }

  console.log("IPv4: none");
  console.log("IPv6: none");
  console.log(`DNS lookup: ${result.durationMs}ms`);
  console.log("Status: ERROR");
  console.log(`Error: ${result.error.message}`);
}

// Formats a list of DNS addresses for terminal output.
function formatAddresses(addresses: string[]): string {
  return addresses.length > 0 ? addresses.join(", ") : "none";
}

// Converts the resolver source into terminal-friendly text.
function formatResolver(resolver: DnsProbeData["resolver"]): string {
  return resolver === "system-fallback" ? "system fallback" : "direct";
}
