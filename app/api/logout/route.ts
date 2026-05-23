import { NextRequest, NextResponse } from "next/server";
import { config } from "@/lib/config";

export async function POST(_req: NextRequest) {
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
