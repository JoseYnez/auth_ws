/**
 * seed-login.ts — Bootstrap de un usuario admin FUNCIONAL para probar el login.
 *
 * El `init.sql` siembra el usuario `system` (sin contraseña), el cliente `demo`
 * y la app `admin-app`, pero NO crea lo que el login necesita: credencial
 * argon2id, contratación con clave de firma, membresía, tripleta ni rol. Eso
 * exige crypto de runtime (argon2id + clave Ed25519 cifrada con el master key),
 * por lo que vive aquí y no en SQL puro.
 *
 * Qué crea (idempotente — re-ejecutable sin romper):
 *   1. auth.users               → usuario admin (user_type='admin')
 *   2. auth.user_credentials    → contraseña argon2id (must_change=false)
 *   3. core.customer_apps       → contrata admin-app para `demo` + clave EdDSA
 *                                 (privada cifrada con PLATFORM_MASTER_KEY)
 *   4. core.customer_users      → membresía usuario↔cliente
 *   5. auth.app_customer_users  → la tripleta (cliente, app, usuario), alias
 *   6. auth.app_customer_user_roles → rol superadmin (platform_only, all perms)
 *
 * USO:
 *   ADMIN_DATABASE_URL="postgresql://postgres:...@localhost:5432/<db>" \
 *     npm run seed:login
 *
 *   ADMIN_DATABASE_URL debe ser un superusuario (o un rol LOGIN miembro de
 *   role_owner): role_auth_service (DATABASE_URL) NO tiene privilegios de
 *   INSERT sobre las tablas de identidad.
 *
 * Configurable por env (con defaults):
 *   SEED_ADMIN_USERNAME (admin)  SEED_ADMIN_EMAIL (admin@demo.local)
 *   SEED_ADMIN_PASSWORD (Admin123!)  SEED_CUSTOMER (demo)  SEED_APP_CODE (admin-app)
 */

import "dotenv/config";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { Client } from "pg";
import { hashPassword } from "../src/core/crypto/password";
import { encryptJson } from "../src/core/crypto/encryption";

const ADMIN_DSN = process.env.ADMIN_DATABASE_URL;
const USERNAME = process.env.SEED_ADMIN_USERNAME ?? "admin";
const EMAIL = process.env.SEED_ADMIN_EMAIL ?? "admin@demo.local";
const PASSWORD = process.env.SEED_ADMIN_PASSWORD ?? "Admin123!";
const CUSTOMER_NAME = process.env.SEED_CUSTOMER ?? "demo";
const APP_CODE = process.env.SEED_APP_CODE ?? "admin-app";
const ALIAS = process.env.SEED_ADMIN_ALIAS ?? "Admin";
const FULL_NAME = process.env.SEED_ADMIN_FULL_NAME ?? "Admin Demo";

async function main(): Promise<void> {
  if (!ADMIN_DSN) {
    throw new Error(
      "Falta ADMIN_DATABASE_URL (DSN de superusuario o rol miembro de role_owner). " +
        "DATABASE_URL usa role_auth_service, que no tiene privilegios de INSERT.",
    );
  }

  // Crypto de runtime: hash de contraseña y clave de firma del par cliente-app.
  const secretHash = await hashPassword(PASSWORD);

  // admin-app firma con Ed25519 (consola admin, decisión #14/§5.1): privada en
  // PKCS8, pública en SPKI, ambas dentro del blob cifrado con el master key.
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const signingKeyEncrypted = encryptJson({
    alg: "EdDSA",
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    kid: randomUUID(),
  });

  const client = new Client({ connectionString: ADMIN_DSN });
  await client.connect();

  try {
    await client.query("BEGIN");
    // Dueño de los objetos: bypassa RLS e inserta en tablas de identidad.
    await client.query("SET ROLE role_owner");
    await client.query("SELECT set_config('audit.app_name', 'bootstrap', true)");
    await client.query("SELECT set_config('audit.action', 'seed_login', true)");

    // --- Resolver lo que ya sembró init.sql ---------------------------------
    const systemId = await scalar(
      client,
      "SELECT id FROM auth.users WHERE username = 'system' AND status = 'active'",
      [],
      "No existe el usuario 'system'. Corre init.sql primero.",
    );
    // A partir de aquí toda escritura se atribuye al usuario system (staff):
    // necesario para crear un user_type='admin' y asignar un rol platform_only.
    await client.query("SELECT set_config('audit.user_id', $1, true)", [systemId]);

    const customerId = await scalar(
      client,
      "SELECT id FROM core.customers WHERE name = $1 AND status <> 'deleted'",
      [CUSTOMER_NAME],
      `No existe el cliente '${CUSTOMER_NAME}'.`,
    );
    const appId = await scalar(
      client,
      "SELECT id FROM core.apps WHERE code = $1 AND status <> 'deleted'",
      [APP_CODE],
      `No existe la app '${APP_CODE}'.`,
    );
    const roleId = await scalar(
      client,
      "SELECT id FROM auth.roles WHERE app_id = $1 AND scope = 'platform_only' AND code = 'superadmin' AND status <> 'deleted'",
      [appId],
      "No existe el rol superadmin de la app (¿falló el trigger de seed?).",
    );

    // --- 1) Usuario admin (idempotente por username) ------------------------
    let userId = await maybeScalar(
      client,
      "SELECT id FROM auth.users WHERE username = $1 AND status <> 'deleted'",
      [USERNAME],
    );
    if (userId === null) {
      userId = await scalar(
        client,
        `INSERT INTO auth.users (username, email, full_name, user_type, email_verified_at, verified_at)
         VALUES ($1, $2, $3, 'admin', now(), now())
         RETURNING id`,
        [USERNAME, EMAIL, FULL_NAME],
        "No se pudo crear el usuario admin.",
      );
    }

    // --- 2) Credencial de contraseña (upsert de la activa) ------------------
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

    // --- 3) Contratación cliente↔app + clave de firma -----------------------
    // No se pisa una clave existente (COALESCE): re-ejecutar mantiene la que ya
    // emite tokens válidos. Si la fila no tenía clave, se rellena.
    await client.query(
      `INSERT INTO core.customer_apps (customer_id, app_id, access_token_signing_key_encrypted)
       VALUES ($1, $2, $3)
       ON CONFLICT (customer_id, app_id) DO UPDATE
         SET access_token_signing_key_encrypted =
               COALESCE(core.customer_apps.access_token_signing_key_encrypted, EXCLUDED.access_token_signing_key_encrypted),
             status = 'active'`,
      [customerId, appId, signingKeyEncrypted],
    );

    // --- 4) Membresía usuario↔cliente ---------------------------------------
    await client.query(
      `INSERT INTO core.customer_users (customer_id, user_id)
       VALUES ($1, $2)
       ON CONFLICT (customer_id, user_id) DO UPDATE SET status = 'active'`,
      [customerId, userId],
    );

    // --- 5) Tripleta (cliente, app, usuario) --------------------------------
    const acuId = await scalar(
      client,
      `INSERT INTO auth.app_customer_users (customer_id, app_id, user_id, name)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (customer_id, app_id, user_id) DO UPDATE SET status = 'active'
       RETURNING id`,
      [customerId, appId, userId, ALIAS],
      "No se pudo crear la tripleta.",
    );

    // --- 6) Rol superadmin sobre la tripleta (índice único parcial: guardado
    // con SELECT en vez de ON CONFLICT) -------------------------------------
    const hasRole = await maybeScalar(
      client,
      "SELECT id FROM auth.app_customer_user_roles WHERE app_customer_user_id = $1 AND role_id = $2 AND status <> 'deleted'",
      [acuId, roleId],
    );
    if (hasRole === null) {
      await client.query(
        "INSERT INTO auth.app_customer_user_roles (app_customer_user_id, role_id) VALUES ($1, $2)",
        [acuId, roleId],
      );
    }

    await client.query("COMMIT");

    console.log("\n✅ Usuario admin listo para login:\n");
    console.log(`   appCode    : ${APP_CODE}`);
    console.log(`   identifier : ${USERNAME}   (o ${EMAIL})`);
    console.log(`   password   : ${PASSWORD}`);
    console.log(`   empresa    : ${CUSTOMER_NAME}`);
    console.log(`   rol        : superadmin (todos los permisos de la app)`);
    console.log("\n   2FA desactivado. Flujo: credenciales → (1 empresa) → sesión.\n");
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
