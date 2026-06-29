const SCANNER_PATTERNS: RegExp[] = [
  /sqlmap/i,
  /nikto/i,
  /nmap/i,
  /masscan/i,
  /zgrab/i,
  /nuclei/i,
  /ffuf/i,
  /gobuster/i,
  /dirbuster/i,
  /wpscan/i,
  /acunetix/i,
  /nessus/i,
  /OpenVAS/i,
  /w3af/i,
  /ZmEu/i,
];

function matchesAny(value: string, patterns: RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(value));
}

/** Blocks known scanner user-agents. Empty UA is allowed (Docker HEALTHCHECK). */
export function isBlockedUserAgent(userAgent: string | null): boolean {
  const value = userAgent?.trim() ?? "";
  if (!value) return false;
  return matchesAny(value, SCANNER_PATTERNS);
}

export function truncateUserAgentForLog(userAgent: string | null): string {
  const value = userAgent?.trim() ?? "";
  if (!value) return "(empty)";
  return value.length > 80 ? `${value.slice(0, 80)}...` : value;
}
