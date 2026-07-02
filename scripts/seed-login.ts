/**
 * seed-login.ts — Rellena SOLO la crypto de runtime sobre el esqueleto que ya
 * sembró `init.sql` (99_seed_bootstrap.sql). No crea estructura.
 *
 * `init.sql` siembra TODO el esqueleto: usuario `system` (actor de auditoría,
 * sin login), usuario `admin` (login), app `admin-app`, las empresas base
 * (`base`, `demo`), y por cada empresa la membresía + contratación (SIN clave de
 * firma) + tripleta + rol superadmin. Lo único que falta es lo que exige crypto
 * de runtime y NO sale en SQL puro:
 *
 *   A. auth.user_credentials                                  → hash argon2id
 *   B. core.customer_apps.access_token_signing_key_encrypted  → blob AES-256-GCM
 *      (UNA clave Ed25519 privada cifrada por par cliente↔app — §5.1)
 *
 * Este script rellena A y B. NO crea usuarios, empresas ni tripletas: si el
 * esqueleto no existe, falla pidiendo correr init.sql. Es idempotente sobre la
 * crypto: re-ejecutar reescribe la contraseña y NO pisa una clave de firma ya
 * presente (solo rellena las que estén en NULL) para no invalidar tokens vivos.
 *
 * USO:
 *   ADMIN_DATABASE_URL="postgresql://postgres:...@localhost:5432/<db>" \
 *     npm run seed:login
 *
 *   ADMIN_DATABASE_URL debe ser un superusuario (o un rol LOGIN miembro de
 *   role_owner): role_auth_service (DATABASE_URL) NO tiene privilegios de
 *   escritura sobre las tablas de identidad.
 *
 * Configurable por env (con defaults):
 *   SEED_ADMIN_USERNAME (admin)   SEED_ADMIN_PASSWORD (Admin123!)
 *   SEED_APP_CODE (admin-app)
 */

import "dotenv/config";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { Client } from "pg";
import { hashPassword } from "../src/core/crypto/password";
import { encryptJson } from "../src/core/crypto/encryption";

const ADMIN_DSN = process.env.ADMIN_DATABASE_URL;
const USERNAME = process.env.SEED_ADMIN_USERNAME ?? "admin";
const PASSWORD = process.env.SEED_ADMIN_PASSWORD ?? "Admin123!";
const APP_CODE = process.env.SEED_APP_CODE ?? "admin-app";

/** Genera un blob cifrado nuevo con una clave Ed25519 fresca (par cliente-app). */
function newSigningKeyEncrypted(): string {
  // admin-app firma con Ed25519 (consola admin, decisión #14/§5.1): privada en
  // PKCS8, pública en SPKI, ambas dentro del blob cifrado con el master key.
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return encryptJson({
    alg: "EdDSA",
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    kid: randomUUID(),
  });
}

async function main(): Promise<void> {
  if (!ADMIN_DSN) {
    throw new Error(
      "Falta ADMIN_DATABASE_URL (DSN de superusuario o rol miembro de role_owner). " +
        "DATABASE_URL usa role_auth_service, que no tiene privilegios de escritura.",
    );
  }

  // Crypto de runtime: hash de contraseña (el de la firma se genera por par).
  const secretHash = await hashPassword(PASSWORD);

  const client = new Client({ connectionString: ADMIN_DSN });
  await client.connect();

  try {
    await client.query("BEGIN");
    // Dueño de los objetos: bypassa RLS y escribe en tablas de identidad.
    await client.query("SET ROLE role_owner");
    await client.query("SELECT set_config('audit.app_name', 'bootstrap', true)");
    await client.query("SELECT set_config('audit.action', 'seed_login', true)");

    // --- Resolver lo que ya sembró init.sql --------------------------------
    const systemId = await scalar(
      client,
      "SELECT id FROM auth.users WHERE username = 'system' AND status = 'active'",
      [],
      "No existe el usuario 'system'. Corre init.sql primero.",
    );
    // Toda escritura se atribuye al usuario system (staff de plataforma).
    await client.query("SELECT set_config('audit.user_id', $1, true)", [systemId]);

    const userId = await scalar(
      client,
      "SELECT id FROM auth.users WHERE username = $1 AND status <> 'deleted'",
      [USERNAME],
      `No existe el usuario de login '${USERNAME}'. Corre init.sql primero.`,
    );
    const appId = await scalar(
      client,
      "SELECT id FROM core.apps WHERE code = $1 AND status <> 'deleted'",
      [APP_CODE],
      `No existe la app '${APP_CODE}'. Corre init.sql primero.`,
    );

    // --- A) Credencial de contraseña (upsert de la activa) -----------------
    const credId = await maybeScalar(
      client,
      "SELECT id FROM auth.user_credentials WHERE user_id = $1 AND credential_type = 'password' AND status = 'active'",
      [userId],
    );
    if (credId === null) {
      await client.query(
        "INSERT INTO auth.user_credentials (user_id, credential_type, secret_hash, must_change_secret) VALUES ($1, 'password', $2, false)",
        [userId, secretHash],
      );
    } else {
      await client.query(
        "UPDATE auth.user_credentials SET secret_hash = $2, must_change_secret = false, failed_login_attempts = 0, locked_until_at = NULL WHERE id = $1",
        [credId, secretHash],
      );
    }

    // --- B) Clave de firma por par cliente↔app (solo las que falten) -------
    // Una clave Ed25519 distinta por cada empresa accesible del usuario en la
    // app. Solo se tocan filas con la clave en NULL: re-ejecutar conserva las
    // que ya emiten tokens válidos.
    const pending = await client.query<{ id: string; customer_name: string }>(
      `SELECT ca.id, c.name AS customer_name
         FROM core.customer_apps ca
         JOIN core.customers c ON c.id = ca.customer_id
         JOIN auth.app_customer_users acu
           ON acu.customer_id = ca.customer_id AND acu.app_id = ca.app_id
        WHERE ca.app_id = $1
          AND acu.user_id = $2
          AND ca.status  <> 'deleted'
          AND acu.status <> 'deleted'
          AND ca.access_token_signing_key_encrypted IS NULL`,
      [appId, userId],
    );
    const signedCompanies: string[] = [];
    for (const row of pending.rows) {
      await client.query(
        // Doble guarda IS NULL: idempotente incluso ante ejecuciones concurrentes.
        "UPDATE core.customer_apps SET access_token_signing_key_encrypted = $2 WHERE id = $1 AND access_token_signing_key_encrypted IS NULL",
        [row.id, newSigningKeyEncrypted()],
      );
      signedCompanies.push(row.customer_name);
    }

    // Empresas accesibles (para el resumen y para confirmar el flujo multi-empresa).
    const tenants = await client.query<{ name: string }>(
      `SELECT c.name
         FROM auth.app_customer_users acu
         JOIN core.customers c ON c.id = acu.customer_id
        WHERE acu.user_id = $1 AND acu.app_id = $2 AND acu.status <> 'deleted'
        ORDER BY c.name`,
      [userId, appId],
    );

    await client.query("COMMIT");

    console.log("\n✅ Crypto de login lista:\n");
    console.log(`   appCode    : ${APP_CODE}`);
    console.log(`   identifier : ${USERNAME}`);
    console.log(`   password   : ${PASSWORD}`);
    console.log(`   empresas   : ${tenants.rows.map((t) => t.name).join(", ") || "(ninguna)"}`);
    console.log(
      `   claves     : ${signedCompanies.length} nueva(s)` +
        (signedCompanies.length ? ` [${signedCompanies.join(", ")}]` : " (ya existían)"),
    );
    console.log(`   rol        : superadmin (todos los permisos de la app)`);
    console.log(
      "\n   2FA desactivado. Flujo: credenciales → selección de empresa → sesión.\n",
    );
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    await client.end();
  }
}

/** Primer valor de la primera fila; lanza si no hay filas. */
async function scalar(
  client: Client,
  sql: string,
  params: unknown[],
  notFoundMsg: string,
): Promise<string> {
  const res = await client.query(sql, params);
  if (res.rows.length === 0) {
    throw new Error(notFoundMsg);
  }
  return res.rows[0][Object.keys(res.rows[0])[0]] as string;
}

/** Primer valor o null si no hay filas. */
async function maybeScalar(
  client: Client,
  sql: string,
  params: unknown[],
): Promise<string | null> {
  const res = await client.query(sql, params);
  if (res.rows.length === 0) {
    return null;
  }
  return res.rows[0][Object.keys(res.rows[0])[0]] as string;
}

main().catch((err) => {
  console.error("\n❌ seed-login falló:", err instanceof Error ? err.message : err);
  process.exit(1);
});
