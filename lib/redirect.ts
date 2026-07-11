import { config } from "./config";

function hasControlChars(value: string): boolean {
  return /[\u0000-\u001f\u007f]/.test(value);
}

export function isRedirectHostAllowed(hostname: string): boolean {
  const normalized = hostname.trim().toLowerCase();
  return config.allowedRedirectHosts.includes(normalized);
}

export function isRedirectAllowed(redirectURL: string): boolean {
  const value = redirectURL.trim();
  if (!value || value === "/") return true;
  if (hasControlChars(value)) return false;

  // Absolute URL: only http(s), and only exact configured hostnames.
  if (/^https?:\/\//i.test(value)) {
    let parsedAbs: URL;
    try {
      parsedAbs = new URL(value);
    } catch {
      return false;
    }

    if (parsedAbs.protocol !== "http:" && parsedAbs.protocol !== "https:") {
      return false;
    }

    return isRedirectHostAllowed(parsedAbs.hostname);
  }

  // Reject protocol-relative URLs and non-http schemes such as javascript:.
  if (/^[a-z][a-z\d+.-]*:/i.test(value)) return false;

  // Relative path: allow only clean root-relative paths (not // or /\).
  if (!value.startsWith("/")) return false;
  if (value.length >= 2 && (value[1] === "/" || value[1] === "\\")) {
    return false;
  }

  return true;
}

function authRoot(): string {
  try {
    const parsed = new URL(config.authDomain);
    return `${parsed.protocol}//${parsed.host}/`;
  } catch {
    return "/";
  }
}

export function determineOriginalURL(
  forwardedProto: string | null,
  forwardedHost: string | null,
  forwardedUri: string | null,
  queryRedirect: string | null,
): string {
  if (queryRedirect && isRedirectAllowed(queryRedirect)) {
    return queryRedirect.trim();
  }

  if (forwardedUri) {
    if (forwardedProto && forwardedHost) {
      const proto = forwardedProto.trim().toLowerCase();
      const host = forwardedHost.trim().toLowerCase();
      const uri = forwardedUri.startsWith("/") ? forwardedUri : `/${forwardedUri}`;
      const candidate = `${proto}://${host}${uri}`;

      if (isRedirectAllowed(candidate)) {
        return candidate;
      }
    }

    return authRoot();
  }

  return authRoot();
}
