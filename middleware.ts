import { NextRequest, NextResponse } from "next/server";
import { verifyTokenEdge } from "./lib/auth-edge";
import { config as authConfig } from "./lib/config";
import { getClientIp } from "./lib/rate-limit";
import { determineOriginalURL, isRedirectAllowed } from "./lib/redirect";
import {
  isBlockedUserAgent,
  resolvePolicy,
  truncateUserAgentForLog,
} from "./lib/user-agent";

/**
 * Builds a per-request Content-Security-Policy with a random nonce.
 * Eliminates 'unsafe-inline' for scripts; style-src keeps 'unsafe-inline'
 * because Tailwind/HeroUI inject critical CSS at runtime.
 */
function buildCsp(nonce: string): string {
  const isDev = process.env.NODE_ENV === "development";
  return [
    "default-src 'self'",
    // 'strict-dynamic' lets trusted nonce-bearing scripts load further scripts.
    // 'unsafe-eval' is added in dev-only for source-map / HMR support.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    // ws:/wss: are needed in development for Next.js Hot Module Replacement.
    `connect-src 'self'${isDev ? " ws: wss:" : ""}`,
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

export async function middleware(req: NextRequest) {
  const forwardedUri = req.headers.get("x-forwarded-uri");
  const forwardedProto = req.headers.get("x-forwarded-proto");
  const forwardedHost = req.headers.get("x-forwarded-host");

  const token = req.cookies.get("auth-token")?.value ?? "";

  const isValid = await verifyTokenEdge(token);

  if (!isValid) {
    const policy = resolvePolicy({
      pathname: req.nextUrl.pathname,
      method: req.method,
      isForwardAuth: forwardedUri !== null,
    });
    if (isBlockedUserAgent(req.headers.get("user-agent"), policy)) {
      const ip = getClientIp(req.headers);
      console.warn(
        `[ua] blocked policy=${policy} ip=${ip} path=${req.nextUrl.pathname} ua=${truncateUserAgentForLog(req.headers.get("user-agent"))}`,
      );
      return new NextResponse(null, { status: 403 });
    }
  }

  // Forward-auth subrequest from Caddy
  if (forwardedUri !== null) {
    if (isValid) {
      return new NextResponse(null, { status: 200 });
    }

    const originalURL = determineOriginalURL(
      forwardedProto,
      forwardedHost,
      forwardedUri,
      req.nextUrl.searchParams.get("redirect"),
    );

    const loginURL = new URL("/", authConfig.authDomain);
    // Validate before reflecting: a tampered x-forwarded-host must not surface
    // as an open redirect parameter even if /api/login would later reject it.
    if (isRedirectAllowed(originalURL)) {
      loginURL.searchParams.set("redirect", originalURL);
    }

    return NextResponse.redirect(loginURL.toString(), { status: 302 });
  }

  // Direct browser visit — inject a per-request nonce for CSP and render page.
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const csp = buildCsp(nonce);

  // Pass nonce to server components via request header; Next.js reads x-nonce
  // and applies it to the inline scripts it generates (RSC flight data, etc.).
  const requestHeaders = new Headers(req.headers);
  requestHeaders.set("x-nonce", nonce);

  const res = NextResponse.next({ request: { headers: requestHeaders } });
  res.headers.set("Content-Security-Policy", csp);
  return res;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon\\.ico).*)"],
};
