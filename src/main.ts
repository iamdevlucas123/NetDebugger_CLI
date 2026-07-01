#!/usr/bin/env node

import { createCli } from "./cli.js";

// Runs the CLI and converts unexpected failures into a non-zero exit code.
async function main(): Promise<void> {
  await createCli().parseAsync(process.argv);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Unexpected error";

  console.error(message);
  process.exitCode = 3;
});
