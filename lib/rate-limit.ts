/**
 * In-memory, per-IP rate limiter for the login endpoint. Suitable for the
 * single-instance standalone deployment used by this service. If the service
 * is ever scaled horizontally, replace this with a shared store (e.g. Redis).
 */

const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;
const MAX_ENTRIES = 10_000;

// Global cap across ALL IPs to slow distributed brute force from many sources.
const GLOBAL_WINDOW_MS = 15 * 60 * 1000;
const GLOBAL_MAX_FAILURES = 100;
const GLOBAL_LOCKOUT_MS = 5 * 60 * 1000;

// Fixed delay applied on a failed attempt to cap guessing throughput.
export const FAILURE_DELAY_MS = 400;

interface Attempt {
  count: number;
  windowStart: number;
  lockedUntil: number;
}

const attempts = new Map<string, Attempt>();

const globalState = {
  failures: 0,
  windowStart: Date.now(),
  lockedUntil: 0,
};

function prune(now: number): void {
  if (attempts.size < MAX_ENTRIES) return;
  for (const [ip, entry] of attempts) {
    const windowExpired = now - entry.windowStart > WINDOW_MS;
    const lockExpired = entry.lockedUntil <= now;
    if (windowExpired && lockExpired) attempts.delete(ip);
  }
}

export function getClientIp(headers: Headers): string {
  // Trust only what the reverse proxy (Caddy) sets authoritatively.
  // X-Real-IP is overwritten by Caddy with the real client_ip, so a
  // client-supplied value cannot spoof it.
  const realIp = headers.get("x-real-ip")?.trim();
  if (realIp) return realIp;

  // Fallback: the LAST X-Forwarded-For entry is the hop added by the nearest
  // trusted proxy. The leftmost entry is client-controlled and must not be
  // used as the rate-limit key.
  const forwardedFor = headers.get("x-forwarded-for");
  if (forwardedFor) {
    const parts = forwardedFor.split(",");
    const last = parts[parts.length - 1]!.trim();
    if (last) return last;
  }

  return "unknown";
}

export interface RateLimitResult {
  allowed: boolean;
  retryAfterSeconds: number;
}

export function checkRateLimit(ip: string): RateLimitResult {
  const now = Date.now();

  if (globalState.lockedUntil > now) {
    console.warn(`[login] global lockout active, rejecting attempt ip=${ip}`);
    return {
      allowed: false,
      retryAfterSeconds: Math.ceil((globalState.lockedUntil - now) / 1000),
    };
  }

  const entry = attempts.get(ip);
  if (!entry) return { allowed: true, retryAfterSeconds: 0 };

  if (entry.lockedUntil > now) {
    return {
      allowed: false,
      retryAfterSeconds: Math.ceil((entry.lockedUntil - now) / 1000),
    };
  }

  if (now - entry.windowStart > WINDOW_MS) {
    attempts.delete(ip);
  }
  return { allowed: true, retryAfterSeconds: 0 };
}

export function recordFailure(ip: string): void {
  const now = Date.now();
  prune(now);

  let entry = attempts.get(ip);
  if (!entry || now - entry.windowStart > WINDOW_MS) {
    entry = { count: 0, windowStart: now, lockedUntil: 0 };
  }

  entry.count += 1;
  if (entry.count >= MAX_ATTEMPTS) {
    entry.lockedUntil = now + LOCKOUT_MS;
  }
  attempts.set(ip, entry);

  if (now - globalState.windowStart > GLOBAL_WINDOW_MS) {
    globalState.failures = 0;
    globalState.windowStart = now;
  }
  globalState.failures += 1;
  if (globalState.failures >= GLOBAL_MAX_FAILURES) {
    globalState.lockedUntil = now + GLOBAL_LOCKOUT_MS;
  }

  console.warn(
    `[login] failed attempt ip=${ip} ip_count=${entry.count} global=${globalState.failures}` +
      (entry.lockedUntil > now ? " ip_locked" : "") +
      (globalState.lockedUntil > now ? " global_locked" : ""),
  );
}

export function recordSuccess(ip: string): void {
  attempts.delete(ip);
}
