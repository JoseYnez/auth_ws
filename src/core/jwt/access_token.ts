import { SignJWT, decodeJwt, importPKCS8, importSPKI, jwtVerify } from "jose";
import type { SigningKey } from "./signing_keys";

// Access token (CLAUDE.md §6): JWT corto con claims sub (user_id), acu
// (app_customer_user_id), customer_id, app_id y sid (session id), firmado con
// la clave del par cliente-app. El tenant viaja SIEMPRE como claim, nunca como
// parámetro. `sid` permite a los resource servers atribuir cada acción a una
// sesión concreta en audit.event_log.app_session_id (no es enforcement de
// revocación: el token se valida localmente sin tocar BD).

const ISSUER = "auth_ws";

export interface AccessTokenClaims {
  readonly sub: string;
  readonly acu: string;
  readonly customerId: string;
  readonly appId: string;
  /** session id = auth.app_customer_user_sessions.id (claim `sid`). */
  readonly sid: string;
}

/** Claims verificados + marcas de tiempo (iat/exp) del propio JWT. */
export interface VerifiedAccessToken extends AccessTokenClaims {
  readonly issuedAt: number;
  readonly expiresAt: number;
}

async function toSignKey(key: SigningKey) {
  return importPKCS8(key.privateKeyPem, "EdDSA");
}

export async function signAccessToken(
  claims: AccessTokenClaims,
  key: SigningKey,
  ttlMinutes: number,
): Promise<string> {
  const jwt = new SignJWT({
    acu: claims.acu,
    customer_id: claims.customerId,
    app_id: claims.appId,
    sid: claims.sid,
  })
    .setProtectedHeader({ alg: key.alg, ...(key.kid ? { kid: key.kid } : {}) })
    .setSubject(claims.sub)
    .setIssuer(ISSUER)
    .setIssuedAt()
    .setExpirationTime(`${ttlMinutes}m`);
  return jwt.sign(await toSignKey(key));
}

/**
 * Lee los claims SIN verificar firma — solo para saber con qué clave de
 * par cliente-app verificar después. Nunca confiar en este resultado.
 */
export function peekAccessTokenClaims(token: string): AccessTokenClaims | null {
  try {
    const payload = decodeJwt(token);
    if (
      typeof payload.sub !== "string" ||
      typeof payload.acu !== "string" ||
      typeof payload.customer_id !== "string" ||
      typeof payload.app_id !== "string" ||
      typeof payload.sid !== "string"
    ) {
      return null;
    }
    return {
      sub: payload.sub,
      acu: payload.acu,
      customerId: payload.customer_id,
      appId: payload.app_id,
      sid: payload.sid,
    };
  } catch {
    return null;
  }
}

/** Verificación real (firma + exp + issuer). Devuelve null si no es válido. */
export async function verifyAccessToken(
  token: string,
  key: SigningKey,
): Promise<VerifiedAccessToken | null> {
  try {
    const verifyKey = await importSPKI(key.publicKeyPem, "EdDSA");
    const { payload } = await jwtVerify(token, verifyKey, {
      issuer: ISSUER,
      algorithms: ["EdDSA"],
    });
    if (
      typeof payload.sub !== "string" ||
      typeof payload.acu !== "string" ||
      typeof payload.customer_id !== "string" ||
      typeof payload.app_id !== "string" ||
      typeof payload.sid !== "string" ||
      typeof payload.iat !== "number" ||
      typeof payload.exp !== "number"
    ) {
      return null;
    }
    return {
      sub: payload.sub,
      acu: payload.acu,
      customerId: payload.customer_id,
      appId: payload.app_id,
      sid: payload.sid,
      issuedAt: payload.iat,
      expiresAt: payload.exp,
    };
  } catch {
    return null;
  }
}
