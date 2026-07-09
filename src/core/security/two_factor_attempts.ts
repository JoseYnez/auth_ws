// Throttle de intentos de 2FA por ticket (jti), en memoria. Complementa el
// rate limit por IP de /auth/two-factor (core/http/rate_limit.ts): acota cuántos
// códigos incorrectos puede absorber UN ticket de login antes de invalidarse,
// cerrando la fuerza bruta de TOTP (10^6 códigos, 3 válidos por ventana). Un
// código incorrecto sigue siendo reintentable hasta el umbral (contrato §2).
//
// Al superar el umbral el ticket se marca consumido en BD (sp_consume_ticket_jti)
// para que muera también en el resto del clúster; este Map solo evita el gasto
// de más verificaciones en la instancia actual.
//
// LIMITACIÓN: el contador vive en el proceso (mismo caveat multi-instancia que
// el rate limiter). El jti quemado en BD sí es global.

const MAX_ATTEMPTS = 5;

interface Entry {
  count: number;
  expiresAt: number; // epoch ms; sigue la vida del ticket
}

const attempts = new Map<string, Entry>();
let lastSweep = Date.now();

function sweep(now: number): void {
  if (now - lastSweep < 60_000) {
    return;
  }
  lastSweep = now;
  for (const [key, entry] of attempts) {
    if (entry.expiresAt <= now) {
      attempts.delete(key);
    }
  }
}

/** ¿El ticket ya agotó sus intentos de 2FA en esta instancia? */
export function isTwoFactorLocked(jtiHash: string): boolean {
  const entry = attempts.get(jtiHash);
  return entry !== undefined && entry.expiresAt > Date.now() && entry.count >= MAX_ATTEMPTS;
}

/**
 * Registra un intento fallido de 2FA para el ticket. Devuelve `locked: true`
 * cuando se alcanza el umbral (el llamador debe invalidar el ticket en BD).
 */
export function registerFailedTwoFactor(
  jtiHash: string,
  ticketExpiresAt: Date,
): { locked: boolean } {
  const now = Date.now();
  sweep(now);
  let entry = attempts.get(jtiHash);
  if (entry === undefined || entry.expiresAt <= now) {
    entry = { count: 0, expiresAt: ticketExpiresAt.getTime() };
    attempts.set(jtiHash, entry);
  }
  entry.count += 1;
  return { locked: entry.count >= MAX_ATTEMPTS };
}

/** Limpia el contador (2FA superado o ticket consumido). */
export function clearTwoFactorAttempts(jtiHash: string): void {
  attempts.delete(jtiHash);
}

export const TWO_FACTOR_MAX_ATTEMPTS = MAX_ATTEMPTS;
