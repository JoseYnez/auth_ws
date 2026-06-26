import { decryptJson } from "../crypto/encryption";

// Formato del plaintext de customer_apps.access_token_signing_key_encrypted
// (el contenido del blob cifrado lo define auth_ws — decisión #14/#15/#18):
//   { "alg": "EdDSA", "privateKeyPem": "<PKCS8>", "publicKeyPem": "<SPKI>", "kid": "..." }
//
// La plataforma firma SIEMPRE con Ed25519 (asimétrica): la clave PRIVADA vive
// cifrada en BD y SOLO auth_ws la descifra y firma; la PÚBLICA se publica como
// JWKS en /auth/.well-known/keys para que cualquier resource server valide sin
// poder emitir tokens (decisión #18). No se admite firma simétrica (HS256): un
// secreto compartido permitiría a quien lo tenga forjar tokens.

export interface SigningKey {
  readonly alg: "EdDSA";
  readonly privateKeyPem: string;
  readonly publicKeyPem: string;
  readonly kid?: string;
}

const CACHE_TTL_MS = 5 * 60 * 1000;

const cache = new Map<string, { key: SigningKey; expiresAt: number }>();

/**
 * Descifra (con caché ≤5 min) la clave de firma de un par cliente-app. Las
 * claves descifradas viven solo en memoria y jamás se loggean ni serializan.
 */
export function getSigningKey(customerId: string, appId: string, encrypted: string): SigningKey {
  const cacheId = `${customerId}:${appId}`;
  const hit = cache.get(cacheId);
  if (hit && hit.expiresAt > Date.now()) {
    return hit.key;
  }
  const key = decryptJson<SigningKey>(encrypted);
  if (key.alg !== "EdDSA") {
    throw new Error("Algoritmo de clave de firma no soportado (solo EdDSA)");
  }
  cache.set(cacheId, { key, expiresAt: Date.now() + CACHE_TTL_MS });
  return key;
}
