import { NextRequest, NextResponse } from "next/server";
import { signToken } from "@/lib/auth";
import { config } from "@/lib/config";
import { isRedirectAllowed } from "@/lib/redirect";

export async function POST(req: NextRequest) {
  let pin: string;
  let redirectURL: string;

  try {
    const body = await req.json() as { pin?: string; redirect?: string };
    pin = body.pin ?? "";
    redirectURL = body.redirect ?? "";
  } catch {
    return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  }

  if (pin !== config.password) {
    return NextResponse.json({ error: "Invalid password" }, { status: 401 });
  }

  const token = signToken();

  const cookieOptions: Parameters<NextResponse["cookies"]["set"]>[0] = {
    name: "auth-token",
    value: token,
    path: "/",
    maxAge: 86400 * 7,
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
