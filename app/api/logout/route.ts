import { NextRequest, NextResponse } from "next/server";
import { config } from "@/lib/config";

/**
 * Returns true only when the request comes from the same origin as the auth
 * service, blocking forced-logout CSRF from cross-site pages.
 *
 * Defence-in-depth rationale: auth-token is SameSite=Lax, so cross-site POST
 * requests do not carry the cookie.  However the Set-Cookie in the *response*
 * (clearing the cookie) would still be applied by some browsers for same-site
 * cross-origin requests.  We therefore gate the endpoint on Sec-Fetch-Site /
 * Origin before touching cookies at all.
 */
function isSameOrigin(req: NextRequest): boolean {
  // Sec-Fetch-Site is always present on fetch() / form POST from modern browsers.
  const secFetchSite = req.headers.get("sec-fetch-site");
  if (secFetchSite !== null) {
    return secFetchSite === "same-origin";
  }

  // Fallback for browsers that predate Sec-Fetch-Site (legacy, rare for POST).
  const origin = req.headers.get("origin");
  if (origin !== null) {
    try {
      const originHost = new URL(origin).hostname.toLowerCase();
      const authHost = new URL(config.authDomain).hostname.toLowerCase();
      return originHost === authHost;
    } catch {
      return false;
    }
  }

  // Neither header is present (non-browser client, curl, scripts).
  // Deny by default — operational logout can be done by clearing the cookie directly.
  return false;
}

export async function POST(req: NextRequest) {
  if (!isSameOrigin(req)) {
    return NextResponse.json({ error: "Доступ запрещён" }, { status: 403 });
  }

  const cookieOptions: Parameters<NextResponse["cookies"]["set"]>[0] = {
    name: "auth-token",
    value: "",
    path: "/",
    maxAge: -1,
    httpOnly: true,
    secure: config.isSecure,
    sameSite: "lax",
  };

  if (config.cookieDomain) {
    cookieOptions.domain = config.cookieDomain;
  }

  const res = NextResponse.json({ ok: true });
  res.cookies.set(cookieOptions);
  return res;
}
