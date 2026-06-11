import { NextRequest, NextResponse } from "next/server";
import { signToken, verifyPassword } from "@/lib/auth";
import { config } from "@/lib/config";
import {
  checkRateLimit,
  getClientIp,
  recordFailure,
  recordSuccess,
} from "@/lib/rate-limit";
import { isRedirectAllowed } from "@/lib/redirect";

export async function POST(req: NextRequest) {
  const ip = getClientIp(req.headers);

  const limit = checkRateLimit(ip);
  if (!limit.allowed) {
    return NextResponse.json(
      { error: "Too many attempts" },
      {
        status: 429,
        headers: { "Retry-After": String(limit.retryAfterSeconds) },
      },
    );
  }

  let pin: string;
  let redirectURL: string;

  try {
    const body = (await req.json()) as { pin?: string; redirect?: string };
    pin = body.pin ?? "";
    redirectURL = body.redirect ?? "";
  } catch {
    return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  }

  if (!verifyPassword(pin)) {
    recordFailure(ip);
    return NextResponse.json({ error: "Invalid password" }, { status: 401 });
  }

  recordSuccess(ip);

  const token = signToken();

  const cookieOptions: Parameters<NextResponse["cookies"]["set"]>[0] = {
    name: "auth-token",
    value: token,
    path: "/",
    maxAge: config.sessionTtlSeconds,
    httpOnly: true,
    secure: config.isSecure,
    sameSite: "lax",
  };

  if (config.cookieDomain) {
    cookieOptions.domain = config.cookieDomain;
  }

  let finalRedirect = redirectURL;
  if (!finalRedirect || !isRedirectAllowed(finalRedirect)) {
    finalRedirect = config.authDomain + "/";
  }

  const res = NextResponse.json({ redirect: finalRedirect });
  res.cookies.set(cookieOptions);
  return res;
}
