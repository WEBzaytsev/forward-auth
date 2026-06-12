import { NextRequest, NextResponse } from "next/server";
import { verifyTokenEdge } from "./lib/auth-edge";
import { config as authConfig } from "./lib/config";
import { determineOriginalURL } from "./lib/redirect";

export async function middleware(req: NextRequest) {
  const forwardedUri = req.headers.get("x-forwarded-uri");
  const forwardedProto = req.headers.get("x-forwarded-proto");
  const forwardedHost = req.headers.get("x-forwarded-host");

  const token = req.cookies.get("auth-token")?.value ?? "";

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

    const loginURL = new URL("/", authConfig.authDomain);
    loginURL.searchParams.set("redirect", originalURL);

    return NextResponse.redirect(loginURL.toString(), { status: 302 });
  }

  // Direct browser visit — let Next.js render the page
  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon\\.ico).*)"],
};
