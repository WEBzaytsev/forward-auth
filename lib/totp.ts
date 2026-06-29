import { verifySync } from "otplib";

const BASE32_RE = /^[A-Z2-7]+=*$/;

/**
 * Validates that a TOTP secret is a well-formed base32 string of sufficient
 * length (≥16 chars ≈ 10 bytes = 80 bits of entropy, Google Authenticator
 * minimum).
 */
export function isValidBase32Secret(secret: string): boolean {
  const cleaned = secret.trim().toUpperCase().replace(/\s/g, "");
  if (cleaned.length < 16) return false;
  return BASE32_RE.test(cleaned);
}

/**
 * Verifies a 6-digit TOTP code against a base32 secret.
 * Uses otplib (RFC 6238, audited @noble/hashes + @scure/base).
 * Default window is ±1 step (30 s each).
 */
export function verifyTotp(secretBase32: string, code: string): boolean {
  const token = code.replace(/\s/g, "");
  if (!/^\d{6}$/.test(token)) return false;

  try {
    const result = verifySync({
      strategy: "totp",
      token,
      secret: secretBase32,
    });
    return result.valid;
  } catch {
    return false;
  }
}
