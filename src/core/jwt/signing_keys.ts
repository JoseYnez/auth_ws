import { decryptJson } from "../crypto/encryption";

// Formato del plaintext de customer_apps.access_token_signing_key_encrypted
// (el contenido del blob cifrado lo define auth_ws — decisión #14/#15):
//   HS256 (apps de negocio):  { "alg": "HS256", "k": "<base64 32B>", "kid": "..." }
//   EdDSA (consola admin):    { "alg": "EdDSA", "privateKeyPem": "<PKCS8>",
//                               "publicKeyPem": "<SPKI>", "kid": "..." }

export type SigningKey =
    | { readonly alg: "HS256"; readonly k: string; readonly kid?: string }
    | {
          readonly alg: "EdDSA";
          readonly privateKeyPem: string;
          readonly publicKeyPem: string;
          readonly kid?: string;
      };

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
    if (key.alg !== "HS256" && key.alg !== "EdDSA") {
        throw new Error("Algoritmo de clave de firma desconocido");
    }
    cache.set(cacheId, { key, expiresAt: Date.now() + CACHE_TTL_MS });
    return key;
}
