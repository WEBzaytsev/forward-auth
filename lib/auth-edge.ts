/**
 * Edge-runtime compatible token verification using Web Crypto API.
 * Mirrors the sign/verify logic of lib/auth.ts but without node:crypto.
 */

import { config } from "./config";
import { isBeforeEpoch, isExpired, parsePayloadString } from "./token";

async function getKey(): Promise<CryptoKey> {
  const enc = new TextEncoder();
  return crypto.subtle.importKey(
    "raw",
    enc.encode(config.sessionSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

function base64urlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (padded.length % 4)) % 4;
  const b64 = padded + "=".repeat(padLen);
  const binary = atob(b64);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export async function verifyTokenEdge(token: string): Promise<boolean> {
  if (!token) return false;

  const parts = token.split(".");
  if (parts.length !== 2) return false;

  const [dataPart, sigPart] = parts;

  let payload: string;
  try {
    payload = new TextDecoder().decode(base64urlDecode(dataPart));
  } catch {
    return false;
  }

  const parsed = parsePayloadString(payload);
  if (!parsed) return false;
  if (isExpired(parsed.issuedAt, config.sessionTtlSeconds)) return false;
  if (isBeforeEpoch(parsed.issuedAt, config.tokenEpoch)) return false;

  try {
    const key = await getKey();
    const expectedSig = await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(payload),
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
