/**
 * Edge-runtime compatible token verification using Web Crypto API.
 * Mirrors the same sign/verify logic as lib/auth.ts but without node:crypto.
 */

const SECRET = process.env.SESSION_SECRET ?? "secret-key-32-bytes-long-minimum";

async function getKey(): Promise<CryptoKey> {
  const enc = new TextEncoder();
  return crypto.subtle.importKey(
    "raw",
    enc.encode(SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

function base64urlEncode(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64urlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (padded.length % 4)) % 4;
  const b64 = padded + "=".repeat(padLen);
  const binary = atob(b64);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;

export async function verifyTokenEdge(token: string): Promise<boolean> {
  if (!token) return false;

  const parts = token.split(".");
  if (parts.length !== 2) return false;

  const [dataPart, sigPart] = parts;

  let timestamp: string;
  try {
    timestamp = new TextDecoder().decode(base64urlDecode(dataPart));
  } catch {
    return false;
  }

  const issuedAt = parseInt(timestamp, 10);
  if (isNaN(issuedAt)) return false;
  if (Math.floor(Date.now() / 1000) - issuedAt > SESSION_TTL_SECONDS) return false;

  try {
    const key = await getKey();
    const expectedSig = await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(timestamp),
    );

    const expectedBytes = new Uint8Array(expectedSig);
    const actualBytes = base64urlDecode(sigPart);

    if (expectedBytes.length !== actualBytes.length) return false;

    let diff = 0;
    for (let i = 0; i < expectedBytes.length; i++) {
      diff |= expectedBytes[i] ^ actualBytes[i];
    }
    return diff === 0;
  } catch {
    return false;
  }
}
