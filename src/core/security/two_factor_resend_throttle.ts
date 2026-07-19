// Throttle de REENVÍOS del código OTP 2FA por ticket (jti), en memoria.
// Complementa el rate limit por IP del endpoint: acota cuántas veces UN ticket
// puede disparar un envío real (SMS/WhatsApp cuestan dinero y el reenvío
// ilimitado habilita SMS-pumping).
//
// Cifras: el ticket vive 5 min → 1 envío inicial + MAX_RESENDS reenvíos con
// COOLDOWN entre ellos llenan la ventana. Agotar los reenvíos NO quema el
// jti (a diferencia de two_factor_attempts): el último código enviado y los
// códigos de recuperación deben seguir siendo canjeables.
//
// LIMITACIÓN: contador por proceso (mismo caveat multi-instancia que el rate
// limiter); el tope de verificación (5 intentos por jti) sí converge en BD.

const MAX_RESENDS = 3;
const COOLDOWN_MS = 60_000;
/** Vida de la entrada: la del ticket de login/enrolamiento (~5 min) + margen. */
const ENTRY_TTL_MS = 6 * 60_000;

interface Entry {
  count: number;
  lastSentAt: number;
  expiresAt: number;
}

const entries = new Map<string, Entry>();
let lastSweep = Date.now();

function sweep(now: number): void {
  if (now - lastSweep < 60_000) {
    return;
  }
  lastSweep = now;
  for (const [key, entry] of entries) {
    if (entry.expiresAt <= now) {
      entries.delete(key);
    }
  }
}

export const RESEND_COOLDOWN_SECONDS = COOLDOWN_MS / 1000;

export type ResendVerdict =
  | { ok: true; remaining: number }
  | { ok: false; reason: "cooldown" | "limit" };

/**
 * Intenta consumir un reenvío para el ticket. El PRIMER envío (el del login o
 * el enroll) no pasa por aquí: solo los reenvíos explícitos del usuario.
 */
export function tryConsumeResend(jtiHash: string): ResendVerdict {
  const now = Date.now();
  sweep(now);
  const entry = entries.get(jtiHash);
  if (entry === undefined || entry.expiresAt <= now) {
    entries.set(jtiHash, { count: 1, lastSentAt: now, expiresAt: now + ENTRY_TTL_MS });
    return { ok: true, remaining: MAX_RESENDS - 1 };
  }
  if (entry.count >= MAX_RESENDS) {
    return { ok: false, reason: "limit" };
  }
  if (now - entry.lastSentAt < COOLDOWN_MS) {
    return { ok: false, reason: "cooldown" };
  }
  entry.count += 1;
  entry.lastSentAt = now;
  return { ok: true, remaining: MAX_RESENDS - entry.count };
}

/** Solo tests: resetea el estado del throttle. */
export function clearResendThrottle(): void {
  entries.clear();
}
