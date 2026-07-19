// Enmascarado del destino del código 2FA para las respuestas del contrato
// (§2.2): el cliente ve a DÓNDE se envió sin recibir el contacto completo.

/**
 * Teléfono en formato E.164 estricto (+ y 8..15 dígitos, sin ceros a la
 * izquierda). Se valida en la frontera (verifiers de auth_ws y admin_ws).
 */
export const E164_PATTERN = /^\+[1-9]\d{7,14}$/u;

/** `+5215512345678` → `+52•••5678` (prefijo corto + últimos 4). */
export function maskPhone(e164: string): string {
  if (e164.length < 6) {
    return "•••";
  }
  return `${e164.slice(0, 3)}•••${e164.slice(-4)}`;
}

/** `yanezluis264@gmail.com` → `y•••@gmail.com`. */
export function maskEmail(email: string): string {
  const at = email.indexOf("@");
  if (at <= 0) {
    return "•••";
  }
  return `${email[0]}•••${email.slice(at)}`;
}
