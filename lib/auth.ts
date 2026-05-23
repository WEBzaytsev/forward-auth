import { createHmac, timingSafeEqual } from "node:crypto";
import { config } from "./config";

export function signToken(): string {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const data = Buffer.from(timestamp).toString("base64url");
  const sig = createHmac("sha256", config.sessionSecret)
    .update(timestamp)
    .digest("base64url");
  return `${data}.${sig}`;
}

export function verifyToken(token: string): boolean {
  if (!token) return false;

  const parts = token.split(".");
  if (parts.length !== 2) return false;

  const [dataPart, sigPart] = parts;

  let timestamp: string;
  try {
    timestamp = Buffer.from(dataPart, "base64url").toString();
  } catch {
    return false;
  }

  const expectedSig = createHmac("sha256", config.sessionSecret)
    .update(timestamp)
    .digest("base64url");

  try {
    return timingSafeEqual(Buffer.from(sigPart), Buffer.from(expectedSig));
  } catch {
    return false;
  }
}
