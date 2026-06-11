/**
 * In-memory, per-IP rate limiter for the login endpoint. Suitable for the
 * single-instance standalone deployment used by this service. If the service
 * is ever scaled horizontally, replace this with a shared store (e.g. Redis).
 */

const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;
const MAX_ENTRIES = 10_000;

interface Attempt {
  count: number;
  windowStart: number;
  lockedUntil: number;
}

const attempts = new Map<string, Attempt>();

function prune(now: number): void {
  if (attempts.size < MAX_ENTRIES) return;
  for (const [ip, entry] of attempts) {
    const windowExpired = now - entry.windowStart > WINDOW_MS;
    const lockExpired = entry.lockedUntil <= now;
    if (windowExpired && lockExpired) attempts.delete(ip);
  }
}

export function getClientIp(headers: Headers): string {
  const forwardedFor = headers.get("x-forwarded-for");
  if (forwardedFor) return forwardedFor.split(",")[0]!.trim();
  return headers.get("x-real-ip")?.trim() || "unknown";
}

export interface RateLimitResult {
  allowed: boolean;
  retryAfterSeconds: number;
}

export function checkRateLimit(ip: string): RateLimitResult {
  const now = Date.now();
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
}

export function recordSuccess(ip: string): void {
  attempts.delete(ip);
}
