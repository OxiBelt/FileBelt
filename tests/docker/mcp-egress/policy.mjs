// SPDX-License-Identifier: Apache-2.0

import { BlockList, isIP } from "node:net";
import { URL } from "node:url";

export const AllowedPorts = new Set([443, 8443]);
export const AllowedTrustProfiles = new Set(["integration", "public"]);

const DeniedIpv4 = new BlockList();
const DeniedIpv6 = new BlockList();
for (const [Network, Prefix, Family] of [
  ["0.0.0.0", 8, "ipv4"],
  ["10.0.0.0", 8, "ipv4"],
  ["100.64.0.0", 10, "ipv4"],
  ["127.0.0.0", 8, "ipv4"],
  ["169.254.0.0", 16, "ipv4"],
  ["172.16.0.0", 12, "ipv4"],
  ["192.0.0.0", 24, "ipv4"],
  ["192.0.2.0", 24, "ipv4"],
  ["192.168.0.0", 16, "ipv4"],
  ["198.18.0.0", 15, "ipv4"],
  ["198.51.100.0", 24, "ipv4"],
  ["203.0.113.0", 24, "ipv4"],
  ["224.0.0.0", 4, "ipv4"],
  ["240.0.0.0", 4, "ipv4"],
  ["::", 128, "ipv6"],
  ["::1", 128, "ipv6"],
  ["::ffff:0:0", 96, "ipv6"],
  ["64:ff9b::", 96, "ipv6"],
  ["100::", 64, "ipv6"],
  ["2001:10::", 28, "ipv6"],
  ["2001:db8::", 32, "ipv6"],
  ["fc00::", 7, "ipv6"],
  ["fe80::", 10, "ipv6"],
  ["ff00::", 8, "ipv6"],
]) {
  (Family === "ipv4" ? DeniedIpv4 : DeniedIpv6).addSubnet(Network, Prefix, Family);
}

export function PrivateAddress(Address) {
  const Version = isIP(Address);
  return Version === 0
    || (Version === 4 ? DeniedIpv4.check(Address, "ipv4") : DeniedIpv6.check(Address, "ipv6"));
}

export function ParseAuthority(Authority) {
  if (Authority.length > 512 || Authority.includes("@") || Authority.includes("/")) {
    throw new Error("invalid authority");
  }
  const Separator = Authority.lastIndexOf(":");
  if (Separator <= 0) {
    throw new Error("port is required");
  }
  const Host = Authority.slice(0, Separator).replace(/^\[|\]$/g, "").toLowerCase();
  const Port = Number(Authority.slice(Separator + 1));
  if (!Host || !AllowedPorts.has(Port) || isIP(Host)) {
    throw new Error("authority is outside the development allowlist");
  }
  return { Host, Port };
}

export function ValidateForwardTarget(TargetValue, MethodValue, TrustProfile, IntegrationHost = "") {
  if (
    typeof TargetValue !== "string"
    || !["GET", "POST"].includes(MethodValue ?? "")
    || !AllowedTrustProfiles.has(TrustProfile ?? "")
  ) {
    throw new Error("forwarding contract is invalid");
  }
  const Target = new URL(TargetValue);
  const Port = Number(Target.port || "443");
  if (
    Target.protocol !== "https:"
    || Target.username
    || Target.password
    || Target.hash
    || !AllowedPorts.has(Port)
    || isIP(Target.hostname)
  ) {
    throw new Error("target is outside the egress policy");
  }
  if (TrustProfile === "integration" && (IntegrationHost.length === 0 || Target.hostname !== IntegrationHost || Port !== 443)) {
    throw new Error("integration target is outside the exact synthetic allowlist");
  }
  return { Port, Target };
}

export function BuildForwardHeaders(RequestHeaders, Target, Port) {
  const Headers = {
    accept: RequestHeaders.accept ?? "application/json",
    "content-type": RequestHeaders["content-type"] ?? "application/octet-stream",
    host: Target.port ? `${Target.hostname}:${Port}` : Target.hostname,
    "user-agent": "FileBelt-MCP-Egress/1",
  };
  for (const Name of ["authorization", "mcp-protocol-version", "mcp-session-id", "x-api-key"]) {
    const Value = RequestHeaders[Name];
    if (typeof Value === "string") {
      Headers[Name] = Value;
    }
  }
  return Headers;
}
