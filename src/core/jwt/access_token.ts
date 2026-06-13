import { createSecretKey } from "node:crypto";
import { SignJWT, decodeJwt, importPKCS8, importSPKI, jwtVerify } from "jose";
import type { SigningKey } from "./signing_keys";

// Access token (CLAUDE.md §6): JWT corto con claims sub (user_id), acu
// (app_customer_user_id), customer_id y app_id, firmado con la clave del par
// cliente-app. El tenant viaja SIEMPRE como claim, nunca como parámetro.

const ISSUER = "auth_ws";

export interface AccessTokenClaims {
    readonly sub: string;
    readonly acu: string;
    readonly customerId: string;
    readonly appId: string;
}

async function toSignKey(key: SigningKey) {
    if (key.alg === "HS256") {
        return createSecretKey(Buffer.from(key.k, "base64"));
    }
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
            typeof payload.app_id !== "string"
        ) {
            return null;
        }
        return {
            sub: payload.sub,
            acu: payload.acu,
            customerId: payload.customer_id,
            appId: payload.app_id,
        };
    } catch {
        return null;
    }
}

/** Verificación real (firma + exp + issuer). Devuelve null si no es válido. */
export async function verifyAccessToken(
    token: string,
    key: SigningKey,
): Promise<AccessTokenClaims | null> {
    try {
        const verifyKey =
            key.alg === "HS256"
                ? createSecretKey(Buffer.from(key.k, "base64"))
                : await importSPKI(key.publicKeyPem, "EdDSA");
        const { payload } = await jwtVerify(token, verifyKey, { issuer: ISSUER });
        if (
            typeof payload.sub !== "string" ||
            typeof payload.acu !== "string" ||
            typeof payload.customer_id !== "string" ||
            typeof payload.app_id !== "string"
        ) {
            return null;
        }
        return {
            sub: payload.sub,
            acu: payload.acu,
            customerId: payload.customer_id,
            appId: payload.app_id,
        };
    } catch {
        return null;
    }
}
