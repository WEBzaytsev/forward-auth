import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { config } from "./config";
import {
  buildPayloadString,
  isBeforeEpoch,
  isExpired,
  parsePayloadString,
} from "./token";

function sign(payload: string): string {
  return createHmac("sha256", config.sessionSecret)
    .update(payload)
    .digest("base64url");
}

export function signToken(): string {
  const issuedAt = Math.floor(Date.now() / 1000);
  const nonce = randomBytes(12).toString("base64url");
  const payload = buildPayloadString(issuedAt, nonce);
  const data = Buffer.from(payload).toString("base64url");
  return `${data}.${sign(payload)}`;
}

export function verifyPassword(pin: string): boolean {
  const provided = Buffer.from(pin);
  const expected = Buffer.from(config.password);
  if (provided.length !== expected.length) return false;
  return timingSafeEqual(provided, expected);
}

export function verifyToken(token: string): boolean {
  if (!token) return false;

  const parts = token.split(".");
  if (parts.length !== 2) return false;

  const [dataPart, sigPart] = parts;

  let payload: string;
  try {
    payload = Buffer.from(dataPart, "base64url").toString();
  } catch {
    return false;
  }

  const parsed = parsePayloadString(payload);
  if (!parsed) return false;
  if (isExpired(parsed.issuedAt, config.sessionTtlSeconds)) return false;
  if (isBeforeEpoch(parsed.issuedAt, config.tokenEpoch)) return false;

  const expectedSig = sign(payload);

  try {
    return timingSafeEqual(Buffer.from(sigPart), Buffer.from(expectedSig));
  } catch {
    return false;
  }
}
