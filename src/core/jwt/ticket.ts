import { createHash, randomUUID } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";
import { config } from "../../config";

// Ticket efímero entre pasos del login (CLAUDE.md §6): JWT de ~5 min firmado
// con clave de PLATAFORMA (no de tenant), stateless. La garantía de un solo
// canje la da la BD: sha256(jti) se registra vía auth.sp_consume_ticket_jti.

const TICKET_TTL_SECONDS = 5 * 60;
const ISSUER = "auth_ws";

export type TicketPurpose = "tenants" | "two-factor" | "change-password";

export interface TicketPayload {
  /** user_id (identidad global) */
  readonly userId: string;
  readonly appId: string;
  readonly appCode: string;
  readonly purpose: TicketPurpose;
  readonly jti: string;
  /** Vence el ticket — viaja a la BD como expires_at del registro del jti */
  readonly expiresAt: Date;
  /** Dispositivo declarado en el login: la sesión se crea con estos datos */
  readonly deviceIdentifier: string;
  readonly deviceName: string | null;
}

let cachedTicketKey: Buffer | null = null;

function ticketKey(): Buffer {
  // sha256 del valor configurado → clave HS256 de 32 bytes estable
  cachedTicketKey ??= createHash("sha256").update(config.platformTicketKey, "utf8").digest();
  return cachedTicketKey;
}

export async function signTicket(
  data: Omit<TicketPayload, "jti" | "expiresAt">,
): Promise<{ ticket: string; jti: string; expiresAt: Date }> {
  const jti = randomUUID();
  const expiresAt = new Date(Date.now() + TICKET_TTL_SECONDS * 1000);
  const ticket = await new SignJWT({
    app_id: data.appId,
    app_code: data.appCode,
    purpose: data.purpose,
    did: data.deviceIdentifier,
    dna: data.deviceName,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(data.userId)
    .setJti(jti)
    .setIssuer(ISSUER)
    .setIssuedAt()
    .setExpirationTime(Math.floor(expiresAt.getTime() / 1000))
    .sign(ticketKey());
  return { ticket, jti, expiresAt };
}

/**
 * Verifica firma, expiración y propósito. Devuelve null ante cualquier fallo
 * (el endpoint responde opaco). El canje one-shot se valida aparte, en la BD.
 */
export async function verifyTicket(
  ticket: string,
  expectedPurpose: TicketPurpose,
): Promise<TicketPayload | null> {
  try {
    const { payload } = await jwtVerify(ticket, ticketKey(), {
      issuer: ISSUER,
      algorithms: ["HS256"],
    });
    if (
      payload.purpose !== expectedPurpose ||
      typeof payload.sub !== "string" ||
      typeof payload.jti !== "string" ||
      typeof payload.app_id !== "string" ||
      typeof payload.app_code !== "string" ||
      typeof payload.did !== "string" ||
      typeof payload.exp !== "number"
    ) {
      return null;
    }
    return {
      userId: payload.sub,
      appId: payload.app_id,
      appCode: payload.app_code,
      purpose: expectedPurpose,
      jti: payload.jti,
      expiresAt: new Date(payload.exp * 1000),
      deviceIdentifier: payload.did,
      deviceName: typeof payload.dna === "string" ? payload.dna : null,
    };
  } catch {
    return null;
  }
}
