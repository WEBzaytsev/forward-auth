import { config } from "./config";

export function isRedirectAllowed(redirectURL: string): boolean {
  if (!redirectURL || redirectURL === "/") return true;

  let parsed: URL;
  try {
    parsed = new URL(redirectURL, "http://placeholder");
  } catch {
    return false;
  }

  // Absolute URL: check scheme
  if (redirectURL.startsWith("http://") || redirectURL.startsWith("https://")) {
    const parsedAbs = new URL(redirectURL);
    const redirectHost = parsedAbs.hostname.toLowerCase();

    let authHost: string;
    try {
      authHost = new URL(config.authDomain).hostname.toLowerCase();
    } catch {
      return false;
    }

    if (redirectHost === authHost) return true;

    if (
      config.cookieDomain &&
      (redirectHost === config.cookieDomain ||
        redirectHost.endsWith(`.${config.cookieDomain}`))
    ) {
      return true;
    }

    return false;
  }

  // Relative path: allow only clean relative paths (not // or /\)
  const p = redirectURL;
  if (!p.startsWith("/")) return false;
  if (p.length >= 2 && (p[1] === "/" || p[1] === "\\")) return false;

  return true;
}

export function determineOriginalURL(
  forwardedProto: string | null,
  forwardedHost: string | null,
  forwardedUri: string | null,
  queryRedirect: string | null,
): string {
  if (queryRedirect && isRedirectAllowed(queryRedirect)) {
    return queryRedirect;
  }

  if (forwardedUri) {
    if (forwardedProto && forwardedHost) {
      return `${forwardedProto}://${forwardedHost}${forwardedUri}`;
    }
    try {
      const parsed = new URL(config.authDomain);
      return `${parsed.protocol}//${parsed.host}/`;
    } catch {
      return "/";
    }
  }

  try {
    const parsed = new URL(config.authDomain);
    return `${parsed.protocol}//${parsed.host}/`;
  } catch {
    return "/";
  }
}
