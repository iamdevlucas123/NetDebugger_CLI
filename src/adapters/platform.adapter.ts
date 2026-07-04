export type RuntimePlatform = "windows" | "unix";

export interface PlatformCommand {
  command: string;
  args: string[];
}

// Detects whether command execution should use Windows or Unix-style tools.
export function detectRuntimePlatform(
  platform: NodeJS.Platform = process.platform,
): RuntimePlatform {
  return platform === "win32" ? "windows" : "unix";
}

// Builds the platform-specific ping command.
export function buildPingCommand(
  host: string,
  count = 4,
  platform: RuntimePlatform = detectRuntimePlatform(),
): PlatformCommand {
  if (platform === "windows") {
    return {
      command: "ping",
      args: ["-n", String(count), host],
    };
  }

  return {
    command: "ping",
    args: ["-c", String(count), host],
  };
}

// Builds the platform-specific traceroute command.
export function buildTracerouteCommand(
  host: string,
  platform: RuntimePlatform = detectRuntimePlatform(),
): PlatformCommand {
  if (platform === "windows") {
    return {
      command: "tracert",
      args: [host],
    };
  }

  return {
    command: "traceroute",
    args: [host],
  };
}
