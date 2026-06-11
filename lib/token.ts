/**
 * Runtime-agnostic token payload helpers shared by the Node (lib/auth.ts)
 * and Edge (lib/auth-edge.ts) verifiers. Contains no crypto or base64 so it
 * stays compatible with both the Node and Edge runtimes.
 *
 * Token wire format: `base64url(payload).base64url(hmac(payload))`
 * where payload = `${VERSION}.${issuedAt}.${nonce}`.
 */

export const TOKEN_VERSION = "v1";

export interface TokenPayload {
  version: string;
  issuedAt: number;
  nonce: string;
}

export function buildPayloadString(issuedAt: number, nonce: string): string {
  return `${TOKEN_VERSION}.${issuedAt}.${nonce}`;
}

export function parsePayloadString(payload: string): TokenPayload | null {
  const segments = payload.split(".");
  if (segments.length !== 3) return null;

  const [version, issuedAtStr, nonce] = segments;
  if (version !== TOKEN_VERSION) return null;
  if (!nonce) return null;

  const issuedAt = parseInt(issuedAtStr, 10);
  if (isNaN(issuedAt)) return null;

  return { version, issuedAt, nonce };
}

export function isExpired(issuedAt: number, ttlSeconds: number): boolean {
  return Math.floor(Date.now() / 1000) - issuedAt > ttlSeconds;
}

// Global revocation lever: tokens issued before the configured epoch are
// rejected. Bumping AUTH_TOKEN_EPOCH invalidates every existing token without
// rotating the secret or using any external store.
export function isBeforeEpoch(issuedAt: number, epochSeconds: number): boolean {
  return epochSeconds > 0 && issuedAt < epochSeconds;
}
