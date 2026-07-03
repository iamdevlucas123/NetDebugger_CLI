import { Command } from "commander";

import { registerDnsCommand } from "./commands/dns.command.js";
import { registerHttpCommand } from "./commands/http.command.js";
import { registerTcpCommand } from "./commands/tcp.command.js";
import { registerTlsCommand } from "./commands/tls.command.js";

// Creates and configures the NetDebugger CLI program.
export function createCli(): Command {
  const program = new Command();

  program
    .name("netdebug")
    .description("Network and HTTP diagnostics from the command line")
    .version("1.0.0")
    .showHelpAfterError();

  registerDnsCommand(program);
  registerTcpCommand(program);
  registerTlsCommand(program);
  registerHttpCommand(program);

  return program;
}
