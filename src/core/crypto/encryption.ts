import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { config } from "../../config";

// AES-256-GCM con PLATFORM_MASTER_KEY (decisión #15 del raíz). Formato del
// texto cifrado: "v1.<iv>.<tag>.<ciphertext>" en base64url — el prefijo de
// versión permite rotar el esquema sin romper datos existentes.
const VERSION = "v1";
const IV_BYTES = 12;

let cachedKey: Buffer | null = null;

function masterKey(): Buffer {
  if (cachedKey === null) {
    const key = Buffer.from(config.platformMasterKey, "base64");
    if (key.length !== 32) {
      throw new Error("PLATFORM_MASTER_KEY debe ser exactamente 32 bytes en base64");
    }
    cachedKey = key;
  }
  return cachedKey;
}

export function encryptText(plain: string): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", masterKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [
    VERSION,
    iv.toString("base64url"),
    tag.toString("base64url"),
    encrypted.toString("base64url"),
  ].join(".");
}

export function decryptText(encryptedValue: string): string {
  const [version, ivB64, tagB64, dataB64] = encryptedValue.split(".");
  if (version !== VERSION || !ivB64 || !tagB64 || !dataB64) {
    throw new Error("Formato de valor cifrado desconocido");
  }
  const decipher = createDecipheriv("aes-256-gcm", masterKey(), Buffer.from(ivB64, "base64url"));
  decipher.setAuthTag(Buffer.from(tagB64, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(dataB64, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}

export function decryptJson<T>(encryptedValue: string): T {
  return JSON.parse(decryptText(encryptedValue)) as T;
}

export function encryptJson(value: unknown): string {
  return encryptText(JSON.stringify(value));
}
