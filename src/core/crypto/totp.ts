import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { URLSearchParams } from "node:url";

// TOTP RFC 6238 (HMAC-SHA1, paso de 30 s, 6 dígitos) implementado con
// node:crypto — sin dependencias. El secreto es el seed base32 estándar de
// las apps authenticator (otpauth://), almacenado cifrado en
// auth.user_two_factor_secrets.secret_encrypted.

const STEP_SECONDS = 30;
const DIGITS = 6;
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/=+$/u, "").replace(/[\s-]/gu, "");
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) {
      throw new Error("Secreto TOTP con caracteres base32 inválidos");
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function hotp(secret: Buffer, counter: number): string {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", secret).update(counterBuffer).digest();
  const offset = (digest[digest.length - 1] ?? 0) & 0x0f;
  const code =
    (((digest[offset] ?? 0) & 0x7f) << 24) |
    (((digest[offset + 1] ?? 0) & 0xff) << 16) |
    (((digest[offset + 2] ?? 0) & 0xff) << 8) |
    ((digest[offset + 3] ?? 0) & 0xff);
  return String(code % 10 ** DIGITS).padStart(DIGITS, "0");
}

/**
 * Verifica un código TOTP con ventana de tolerancia ±1 paso (desfase de
 * reloj del dispositivo). Comparación en tiempo constante.
 */
export function verifyTotpCode(secretBase32: string, code: string, window = 1): boolean {
  if (!/^\d{6}$/u.test(code)) {
    return false;
  }
  const secret = base32Decode(secretBase32);
  const currentStep = Math.floor(Date.now() / 1000 / STEP_SECONDS);
  const codeBuffer = Buffer.from(code, "utf8");
  for (let offset = -window; offset <= window; offset++) {
    const expected = Buffer.from(hotp(secret, currentStep + offset), "utf8");
    if (expected.length === codeBuffer.length && timingSafeEqual(expected, codeBuffer)) {
      return true;
    }
  }
  return false;
}

/**
 * Genera un secreto TOTP nuevo en base32 (160 bits, recomendación RFC 4226).
 * El valor crudo se muestra al usuario una vez (QR / entrada manual) y se
 * almacena cifrado en auth.user_two_factor_secrets.secret_encrypted.
 */
export function generateTotpSecretBase32(): string {
  return base32Encode(randomBytes(20));
}

/**
 * URI `otpauth://totp/...` estándar para que las apps authenticator importen el
 * secreto por QR. `issuer` y `accountName` solo etiquetan la entrada.
 */
export function buildOtpauthUri(
  secretBase32: string,
  accountName: string,
  issuer: string,
): string {
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  const params = new URLSearchParams({
    secret: secretBase32,
    issuer,
    algorithm: "SHA1",
    digits: String(DIGITS),
    period: String(STEP_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}
