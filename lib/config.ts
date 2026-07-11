import { isValidBase32Secret } from "./totp";

const MIN_PASSWORD_LENGTH = 6;
const MIN_SECRET_LENGTH = 32;
const SESSION_TTL_SECONDS = 24 * 60 * 60;

// Known placeholder/example secrets that must never be used in production.
const FORBIDDEN_SECRETS = new Set([
  "secret-key-32-bytes-long-minimum",
  "your-secret-key-32-bytes-minimum",
  "your-super-secret-key-32-bytes-long",
  "any-32-chars-secret-for-local-dev",
]);

// During the Docker image build the runtime env vars are not present yet
// (.dockerignore excludes .env*, secrets are injected at run time). Skip the
// hard fail-closed checks in that phase; they run at server startup instead.
const isBuildPhase = process.env.NEXT_PHASE === "phase-production-build";

const password = process.env.AUTH_PASSWORD ?? "";
const sessionSecret = process.env.SESSION_SECRET ?? "";
const authDomain = process.env.AUTH_DOMAIN ?? "http://localhost:8080";
// Optional: operator-supplied cookie domain, useful for multi-segment TLDs
// such as example.co.uk where the two-label heuristic would produce co.uk
// (a public suffix that browsers refuse). Provide without a leading dot.
const explicitCookieDomain = process.env.COOKIE_DOMAIN?.trim() ?? "";
const allowedRedirectHostsRaw = process.env.ALLOWED_REDIRECT_HOSTS ?? "";

const parsedEpoch = parseInt(process.env.AUTH_TOKEN_EPOCH ?? "", 10);
const tokenEpoch = Number.isNaN(parsedEpoch) || parsedEpoch < 0 ? 0 : parsedEpoch;
const totpSecret = process.env.TOTP_SECRET?.trim() ?? "";

const HOSTNAME_RE = /^(localhost|\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*)$/;

function normalizeHostname(value: string): string | null {
  const trimmed = value.trim().toLowerCase().replace(/^\.+/, "");
  if (!trimmed) return null;

  let hostname: string;
  try {
    if (/^https?:\/\//i.test(trimmed)) {
      hostname = new URL(trimmed).hostname.toLowerCase();
    } else {
      // Keep ALLOWED_REDIRECT_HOSTS boring: exact hostnames only, no paths,
      // schemes other than http(s), credentials, ports, or wildcard suffixes.
      if (trimmed.includes("/") || trimmed.includes("@") || trimmed.includes(":")) {
        return null;
      }
      hostname = trimmed;
    }
  } catch {
    return null;
  }

  if (!HOSTNAME_RE.test(hostname)) return null;
  return hostname;
}

function getAuthHostname(domain: string): string {
  try {
    const parsed = new URL(domain);
    return parsed.hostname.toLowerCase();
  } catch {
    return "localhost";
  }
}

function parseAllowedRedirectHosts(raw: string, domain: string): string[] {
  const hosts = new Set<string>([getAuthHostname(domain)]);

  for (const item of raw.split(",")) {
    const value = item.trim();
    if (!value) continue;

    const hostname = normalizeHostname(value);
    if (!hostname) {
      throw new Error(
        `ALLOWED_REDIRECT_HOSTS: недопустимый хост "${value}". Укажите точные hostnames через запятую, например: app.example.com,admin.example.com`,
      );
    }
    hosts.add(hostname);
  }

  return [...hosts];
}

const allowedRedirectHosts = parseAllowedRedirectHosts(
  allowedRedirectHostsRaw,
  authDomain,
);

function assertConfig(): void {
  if (isBuildPhase) return;

  let authUrl: URL;
  try {
    authUrl = new URL(authDomain);
  } catch {
    throw new Error(
      "AUTH_DOMAIN: укажите полный публичный URL сервиса входа, например https://auth.example.com",
    );
  }
  if (authUrl.protocol !== "http:" && authUrl.protocol !== "https:") {
    throw new Error("AUTH_DOMAIN: разрешены только http:// или https:// URL");
  }
  if (process.env.NODE_ENV === "production" && authUrl.protocol !== "https:") {
    throw new Error("AUTH_DOMAIN: в production требуется https://, иначе Secure cookie не будет работать корректно");
  }

  if (!password) {
    throw new Error(
      "AUTH_PASSWORD обязателен: задайте код доступа через переменную окружения",
    );
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new Error(
      `AUTH_PASSWORD: код доступа должен быть не короче ${MIN_PASSWORD_LENGTH} символов`,
    );
  }

  if (!sessionSecret) {
    throw new Error(
      "SESSION_SECRET обязателен: задайте ключ подписи cookie через переменную окружения",
    );
  }
  if (sessionSecret.length < MIN_SECRET_LENGTH) {
    throw new Error(
      `SESSION_SECRET: ключ должен быть не короче ${MIN_SECRET_LENGTH} байт`,
    );
  }
  if (FORBIDDEN_SECRETS.has(sessionSecret)) {
    throw new Error(
      "SESSION_SECRET — известный плейсхолдер. Сгенерируйте уникальный ключ: openssl rand -base64 48",
    );
  }

  if (totpSecret && !isValidBase32Secret(totpSecret)) {
    throw new Error(
      "TOTP_SECRET: недопустимый формат (ожидается base32, минимум 16 символов)",
    );
  }
}

assertConfig();

function computeCookieDomain(domain: string): string {
  // Operator-supplied value takes absolute precedence; bypasses the heuristic
  // entirely, which is required for multi-segment TLDs (e.g. example.co.uk).
  if (explicitCookieDomain) return explicitCookieDomain;

  let hostname: string;
  try {
    hostname = new URL(domain).hostname;
  } catch {
    return "";
  }

  if (hostname === "localhost") return hostname;

  // Check if it's an IP address (simple heuristic)
  if (/^[\d.]+$/.test(hostname) || hostname.includes(":")) return hostname;

  const parts = hostname.split(".");
  if (parts.length >= 2) {
    return `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  }
  return hostname;
}

export const config = {
  password,
  sessionSecret,
  authDomain,
  cookieDomain: computeCookieDomain(authDomain),
  allowedRedirectHosts,
  pinLength: password.length,
  sessionTtlSeconds: SESSION_TTL_SECONDS,
  tokenEpoch,
  totpSecret,
  totpEnabled: totpSecret.length > 0,
  // Always mark the cookie Secure in production, and whenever the auth domain
  // is served over https. Never fall back to an insecure cookie in prod.
  isSecure: authDomain.startsWith("https:") || process.env.NODE_ENV === "production",
};
