import { createHmac } from "node:crypto";

const password = process.env.AUTH_PASSWORD ?? "1234";
const sessionSecret = process.env.SESSION_SECRET ?? "secret-key-32-bytes-long-minimum";
const authDomain = process.env.AUTH_DOMAIN ?? "http://localhost:8080";

if (password.length < 4) {
  throw new Error("AUTH_PASSWORD must be at least 4 characters long");
}

function computeCookieDomain(domain: string): string {
  let hostname: string;
  try {
    hostname = new URL(domain).hostname;
  } catch {
    return "";
  }

  if (hostname === "localhost") return hostname;

  // Check if it's an IP address (simple heuristic)
  if (/^[\d.]+$/.test(hostname) || hostname.includes(":")) return hostname;

  const parts = hostname.split(".");
  if (parts.length >= 2) {
    return `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  }
  return hostname;
}

export const config = {
  password,
  sessionSecret,
  authDomain,
  cookieDomain: computeCookieDomain(authDomain),
  pinLength: password.length,
  isSecure: authDomain.startsWith("https:"),
};
