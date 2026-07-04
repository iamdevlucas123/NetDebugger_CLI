import { Command } from "commander";

import { registerCompareCommand } from "./commands/compare.command.js";
import { registerDoctorCommand } from "./commands/doctor.command.js";
import { registerDnsCommand } from "./commands/dns.command.js";
import { registerHttpCommand } from "./commands/http.command.js";
import { registerPingCommand } from "./commands/ping.command.js";
import { registerTcpCommand } from "./commands/tcp.command.js";
import { registerTlsCommand } from "./commands/tls.command.js";
import { registerTraceCommand } from "./commands/trace.command.js";

// Creates and configures the NetDebugger CLI program.
export function createCli(): Command {
  const program = new Command();

  program
    .name("netdebug")
    .description("Network and HTTP diagnostics from the command line")
    .version("1.0.0")
    .showHelpAfterError();

  registerDoctorCommand(program);
  registerCompareCommand(program);
  registerDnsCommand(program);
  registerTcpCommand(program);
  registerTlsCommand(program);
  registerHttpCommand(program);
  registerPingCommand(program);
  registerTraceCommand(program);

  return program;
}
