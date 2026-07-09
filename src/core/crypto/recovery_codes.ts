import { randomBytes } from "node:crypto";

// Códigos de recuperación 2FA de un solo uso (CLAUDE.md §2.2 / tabla
// auth.user_two_factor_recovery_codes). Se muestran UNA vez al usuario en el
// enrolamiento; la BD solo guarda sha256(normalize(code)). La normalización
// (mayúsculas, sin separadores) hace la verificación tolerante a cómo el
// usuario reescriba el código (con o sin guion, mayúsculas/minúsculas).

// Alfabeto sin caracteres ambiguos (0/O, 1/I/L) para lectura/transcripción.
const ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const CODE_COUNT = 10;
const CODE_CHARS = 10; // 10 chars → mostrados como XXXXX-XXXXX

/** Normaliza un código para hashear/verificar: mayúsculas y solo [A-Z0-9]. */
export function normalizeRecoveryCode(code: string): string {
  return code.toUpperCase().replace(/[^A-Z0-9]/gu, "");
}

function randomCode(): string {
  const bytes = randomBytes(CODE_CHARS);
  let raw = "";
  for (let i = 0; i < CODE_CHARS; i++) {
    raw += ALPHABET[(bytes[i] ?? 0) % ALPHABET.length];
  }
  // Formato legible XXXXX-XXXXX (el guion se ignora al normalizar).
  return `${raw.slice(0, 5)}-${raw.slice(5)}`;
}

/** Genera un lote de códigos de recuperación crudos (para mostrar al usuario). */
export function generateRecoveryCodes(count = CODE_COUNT): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    codes.push(randomCode());
  }
  return codes;
}
