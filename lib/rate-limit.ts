/**
 * In-memory, per-IP rate limiter for the login endpoint. Suitable for the
 * single-instance standalone deployment used by this service. If the service
 * is ever scaled horizontally, replace this with a shared store (e.g. Redis).
 */

const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;
const MAX_ENTRIES = 10_000;

// Global progressive penalty: no hard lockout (which is a DoS vector against
// the login page itself). Instead, each failed attempt past the threshold adds
// GLOBAL_DELAY_STEP_MS to the per-attempt delay, capped at GLOBAL_DELAY_MAX_MS.
// Legitimate users with the correct PIN are unaffected — the delay is only
// applied after a failed password check.
const GLOBAL_WINDOW_MS = 15 * 60 * 1000;
const GLOBAL_FAILURE_THRESHOLD = 50;
const GLOBAL_DELAY_STEP_MS = 100;
const GLOBAL_DELAY_MAX_MS = 5_000;

// Fixed delay applied on every failed attempt.
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
};

/**
 * Returns the extra milliseconds that should be added to the failure delay
 * based on the current global failure count.  Zero below the threshold;
 * rises linearly above it, capped at GLOBAL_DELAY_MAX_MS.
 */
export function getGlobalDelayMs(): number {
  const excess = Math.max(0, globalState.failures - GLOBAL_FAILURE_THRESHOLD);
  return Math.min(excess * GLOBAL_DELAY_STEP_MS, GLOBAL_DELAY_MAX_MS);
}

function prune(now: number): void {
  if (attempts.size < MAX_ENTRIES) return;
  for (const [ip, entry] of attempts) {
    const windowExpired = now - entry.windowStart > WINDOW_MS;
    const lockExpired = entry.lockedUntil <= now;
    if (windowExpired && lockExpired) attempts.delete(ip);
  }
}

export function getClientIp(headers: Headers): string {
  // Trusted only because Caddy overwrites X-Real-IP with the real client_ip.
  // No fallback to X-Forwarded-For: it is client-spoofable without a trusted
  // proxy. If X-Real-IP is absent (misconfig / direct access), fail safe to a
  // single shared bucket rather than trusting a forgeable value.
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

  if (now - globalState.windowStart > GLOBAL_WINDOW_MS) {
    globalState.failures = 0;
    globalState.windowStart = now;
  }
  globalState.failures += 1;

  const globalDelay = getGlobalDelayMs();
  console.warn(
    `[login] failed attempt ip=${ip} ip_count=${entry.count} global=${globalState.failures}` +
      (entry.lockedUntil > now ? " ip_locked" : "") +
      (globalDelay > 0 ? ` global_extra_delay=${globalDelay}ms` : ""),
  );
}

export function recordSuccess(ip: string): void {
  attempts.delete(ip);
}
