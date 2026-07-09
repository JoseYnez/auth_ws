import { createHash, randomUUID } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";
import { config } from "../../config";

// Ticket de enrolamiento de 2FA: JWT corto firmado con la clave de PLATAFORMA
// (no de tenant), emitido tras aceptar la invitación (fijar contraseña). Autoriza
// los pasos POST /auth/two-factor/enroll y /confirm sin que el usuario tenga aún
// sesión (todavía no eligió empresa). No es one-shot: enroll y confirm lo reusan
// dentro de su vigencia. TTL más holgado que el de login (enrolar toma tiempo).

const TICKET_TTL_SECONDS = 30 * 60;
const ISSUER = "auth_ws";
const PURPOSE = "enroll-2fa";

export interface EnrollmentTicket {
  readonly userId: string;
  /** Etiqueta para el URI otpauth (email del usuario). */
  readonly accountName: string;
}

let cachedKey: Buffer | null = null;

function ticketKey(): Buffer {
  cachedKey ??= createHash("sha256").update(config.platformTicketKey, "utf8").digest();
  return cachedKey;
}

export async function signEnrollmentTicket(userId: string, accountName: string): Promise<string> {
  return new SignJWT({ purpose: PURPOSE, acc: accountName })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(userId)
    .setJti(randomUUID())
    .setIssuer(ISSUER)
    .setIssuedAt()
    .setExpirationTime(`${TICKET_TTL_SECONDS}s`)
    .sign(ticketKey());
}

/** Verifica firma, expiración y propósito. Devuelve null ante cualquier fallo. */
export async function verifyEnrollmentTicket(ticket: string): Promise<EnrollmentTicket | null> {
  try {
    const { payload } = await jwtVerify(ticket, ticketKey(), {
      issuer: ISSUER,
      algorithms: ["HS256"],
    });
    if (
      payload.purpose !== PURPOSE ||
      typeof payload.sub !== "string" ||
      typeof payload.acc !== "string"
    ) {
      return null;
    }
    return { userId: payload.sub, accountName: payload.acc };
  } catch {
    return null;
  }
}
