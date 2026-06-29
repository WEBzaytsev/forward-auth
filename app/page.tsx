import { cookies } from "next/headers";
import { AuthorizedView } from "@/components/AuthorizedView";
import { LoginForm } from "@/components/LoginForm";
import { verifyToken } from "@/lib/auth";
import { config } from "@/lib/config";
import { determineOriginalURL } from "@/lib/redirect";
import type { SearchParams } from "@/lib/types";

export default async function Home({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const cookieStore = await cookies();
  const token = cookieStore.get("auth-token")?.value ?? "";
  const isAuthorized = verifyToken(token);

  const params = await searchParams;
  const queryRedirect = typeof params.redirect === "string" ? params.redirect : null;
  const redirectURL = determineOriginalURL(null, null, null, queryRedirect);

  if (isAuthorized) {
    return <AuthorizedView />;
  }

  return <LoginForm pinLength={config.pinLength} redirectURL={redirectURL} totpEnabled={config.totpEnabled} />;
}
