import argon2 from "argon2";

// Parámetros OWASP 2024 para argon2id. El prefijo PHC resultante ($argon2id$)
// está whitelisteado por ck_user_credentials_secret_hash_format en la BD.
const ARGON2_OPTIONS: argon2.Options = {
    type: argon2.argon2id,
    memoryCost: 19456, // KiB (19 MiB)
    timeCost: 2,
    parallelism: 1,
};

export async function hashPassword(plain: string): Promise<string> {
    return argon2.hash(plain, ARGON2_OPTIONS);
}

export async function verifyPassword(hash: string, plain: string): Promise<boolean> {
    try {
        return await argon2.verify(hash, plain);
    } catch {
        // hash corrupto/formato desconocido: jamás dejar pasar
        return false;
    }
}

let dummyHashPromise: Promise<string> | null = null;

/**
 * Verificación contra un hash dummy para igualar tiempos cuando el usuario
 * no existe o no tiene credencial (respuestas opacas, CLAUDE.md §7): el
 * atacante no debe poder distinguir "usuario inexistente" de "contraseña
 * mala" por la latencia.
 */
export async function verifyAgainstDummy(plain: string): Promise<void> {
    dummyHashPromise ??= argon2.hash("dummy-timing-equalizer", ARGON2_OPTIONS);
    const dummyHash = await dummyHashPromise;
    await verifyPassword(dummyHash, plain);
}
