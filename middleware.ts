import { NextRequest, NextResponse } from "next/server";
import { verifyTokenEdge } from "./lib/auth-edge";

const AUTH_DOMAIN = process.env.AUTH_DOMAIN ?? "http://localhost:8080";

function determineOriginalURL(
  forwardedProto: string | null,
  forwardedHost: string | null,
  forwardedUri: string | null,
  queryRedirect: string | null,
): string {
  if (queryRedirect) return queryRedirect;

  if (forwardedUri && forwardedProto && forwardedHost) {
    return `${forwardedProto}://${forwardedHost}${forwardedUri}`;
  }

  try {
    const parsed = new URL(AUTH_DOMAIN);
    return `${parsed.protocol}//${parsed.host}/`;
  } catch {
    return "/";
  }
}

export async function middleware(req: NextRequest) {
  const forwardedUri = req.headers.get("x-forwarded-uri");
  const forwardedProto = req.headers.get("x-forwarded-proto");
  const forwardedHost = req.headers.get("x-forwarded-host");

  const token =
    req.cookies.get("auth-token")?.value ??
    req.headers.get("x-auth-token") ??
    "";

  const isValid = await verifyTokenEdge(token);

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

    const loginURL = new URL("/", AUTH_DOMAIN);
    loginURL.searchParams.set("redirect", originalURL);

    return NextResponse.redirect(loginURL.toString(), { status: 302 });
  }

  // Direct browser visit — let Next.js render the page
  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon\\.ico).*)"],
};
