// Anti-replay de TOTP por usuario, en memoria (RELEASE_PLAN 5.3). Un código
// TOTP es válido durante toda su ventana (±1 paso de 30 s): sin esta pieza, un
// código interceptado puede reutilizarse dentro de ese margen. Se recuerda el
// último time-step (contador RFC 6238) aceptado por usuario y se rechaza
// cualquier código cuyo step no sea estrictamente mayor — el reuso del mismo
// step se trata como código incorrecto (respuesta opaca, sin filtrar el motivo).
//
// Los códigos de recuperación NO pasan por aquí: su one-shot ya lo garantiza
// la BD (auth.sp_consume_recovery_code).
//
// LIMITACIÓN: el registro vive en el proceso (mismo caveat multi-instancia que
// core/http/rate_limit.ts y two_factor_attempts.ts): con varias instancias, el
// replay solo se corta dentro de la misma instancia. Para un corte global,
// sustituir el Map por un store compartido (Redis) — ver Fase 5 del plan.

// Un step aceptado deja de ser relevante en cuanto la ventana de verificación
// (±1 paso de 30 s) lo deja atrás; 5 minutos de vida cubren eso con holgura.
const ENTRY_TTL_MS = 5 * 60_000;

interface Entry {
  lastStep: number; // último time-step TOTP aceptado para el usuario
  expiresAt: number; // epoch ms
}

const acceptedSteps = new Map<string, Entry>();
let lastSweep = Date.now();

function sweep(now: number): void {
  if (now - lastSweep < 60_000) {
    return;
  }
  lastSweep = now;
  for (const [key, entry] of acceptedSteps) {
    if (entry.expiresAt <= now) {
      acceptedSteps.delete(key);
    }
  }
}

/**
 * Registra el time-step TOTP aceptado para el usuario si es más nuevo que el
 * último recordado. Devuelve `false` cuando el step ya fue usado (replay): el
 * llamador debe tratar el código como incorrecto.
 */
export function tryAcceptTotpStep(userId: string, step: number): boolean {
  const now = Date.now();
  sweep(now);
  const entry = acceptedSteps.get(userId);
  if (entry !== undefined && entry.expiresAt > now && step <= entry.lastStep) {
    return false;
  }
  acceptedSteps.set(userId, { lastStep: step, expiresAt: now + ENTRY_TTL_MS });
  return true;
}
