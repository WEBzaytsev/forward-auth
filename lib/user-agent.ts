export type UserAgentPolicy = "strict" | "default" | "minimal";

const CLI_AND_SCRIPT_PATTERNS: RegExp[] = [
  /curl\//i,
  /Wget\//i,
  /HTTPie\//i,
  /Go-http-client/i,
  /python-requests/i,
  /aiohttp/i,
  /urllib/i,
  /libwww-perl/i,
  /Java\//i,
  /okhttp/i,
  /axios\//i,
];

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

const HEADLESS_PATTERNS: RegExp[] = [
  /HeadlessChrome/i,
  /PhantomJS/i,
  /Puppeteer/i,
];

function matchesAny(value: string, patterns: RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(value));
}

function isEmptyUserAgent(userAgent: string | null): boolean {
  return (userAgent?.trim() ?? "") === "";
}

export function resolvePolicy(input: {
  pathname: string;
  method: string;
  isForwardAuth: boolean;
}): UserAgentPolicy {
  if (input.method === "POST" && input.pathname === "/api/login") {
    return "strict";
  }
  if (input.isForwardAuth) {
    return "minimal";
  }
  return "default";
}

export function isBlockedUserAgent(
  userAgent: string | null,
  policy: UserAgentPolicy,
): boolean {
  const value = userAgent?.trim() ?? "";

  if (policy === "strict") {
    if (isEmptyUserAgent(userAgent)) return true;
    if (matchesAny(value, CLI_AND_SCRIPT_PATTERNS)) return true;
    if (matchesAny(value, SCANNER_PATTERNS)) return true;
    if (matchesAny(value, HEADLESS_PATTERNS)) return true;
    return false;
  }

  if (policy === "minimal") {
    if (matchesAny(value, CLI_AND_SCRIPT_PATTERNS)) return true;
    if (matchesAny(value, SCANNER_PATTERNS)) return true;
    return false;
  }

  if (matchesAny(value, SCANNER_PATTERNS)) return true;
  return false;
}

export function truncateUserAgentForLog(userAgent: string | null): string {
  const value = userAgent?.trim() ?? "";
  if (!value) return "(empty)";
  return value.length > 80 ? `${value.slice(0, 80)}...` : value;
}
