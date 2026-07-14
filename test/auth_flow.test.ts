/**
 * auth_flow.test.ts — Suite de integración del flujo de auth (Fase 6.4).
 *
 * Construye la app Fastify en proceso (buildApp) y ejercita el contrato de §2.2
 * con app.inject() contra el Postgres de PRUEBA sembrado (test/setup.ts). Los
 * tests son SECUENCIALES y comparten estado (ticket, cookie de refresh, access
 * token): el orden importa (login → sesión → verify → refresh → switch → logout).
 *
 * NO se ejecutan flujos que muten el estado sembrado del admin
 * (password-reset/confirm, change-password): romperían el resto de la suite.
 */

import type { FastifyInstance } from "fastify";
import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildApp } from "../src/server";

// DSN de superusuario SOLO para el bootstrap del test: los pasos negativos
// (opacidad, i18n) consumen el presupuesto de intentos fallidos del admin
// (max_failed_login_attempts=3) y lo bloquearían 15 min, haciendo la suite no
// idempotente. Reseteamos el lockout antes y después de la corrida. Nunca se usa
// en el servicio (auth_ws conecta como role_auth_service, sin escritura).
const ADMIN_DSN =
  process.env.TEST_ADMIN_DATABASE_URL ?? "postgresql://postgres:postgres@localhost:5433/core_db";

/**
 * Limpia el contador de intentos fallidos y el lockout de la credencial del
 * admin, replicando el patrón de seed-login (role_owner + contexto de auditoría,
 * requerido por fn_enforce_user_protection sobre usuarios protegidos).
 */
async function resetAdminLockout(): Promise<void> {
  const client = new Client({ connectionString: ADMIN_DSN });
  await client.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET ROLE role_owner");
    await client.query("SELECT set_config('audit.app_name', 'test', true)");
    await client.query("SELECT set_config('audit.action', 'reset_admin_lockout', true)");
    const sys = await client.query("SELECT id FROM auth.users WHERE username = 'system'");
    await client.query("SELECT set_config('audit.user_id', $1, true)", [sys.rows[0].id]);
    await client.query(
      `UPDATE auth.user_credentials uc
          SET failed_login_attempts = 0, locked_until_at = NULL
         FROM auth.users u
        WHERE uc.user_id = u.id
          AND u.username = 'admin'
          AND uc.credential_type = 'password'
          AND uc.status = 'active'`,
    );
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    await client.end();
  }
}

const CREDS = {
  appCode: "admin-app",
  identifier: "admin",
  password: "Admin123!",
  deviceIdentifier: "vitest-device",
  deviceName: "vitest",
};

let app: FastifyInstance;

// Estado compartido entre los pasos del flujo.
let ticket = "";
let platformId = "";
let demoId = "";
let refreshCookie = "";
let accessToken = "";

/** Extrae el valor de la cookie de refresh de una respuesta de inject. */
function readRefreshCookie(res: Awaited<ReturnType<FastifyInstance["inject"]>>): {
  value: string;
  httpOnly: boolean;
} {
  const cookie = res.cookies.find((c) => c.name === "auth_refresh");
  if (cookie === undefined) {
    throw new Error("La respuesta no trae cookie auth_refresh");
  }
  return { value: cookie.value, httpOnly: cookie.httpOnly === true };
}

beforeAll(async () => {
  // Deja la credencial del admin limpia antes de empezar (por si una corrida
  // previa la dejó bloqueada): el primer login debe poder autenticar.
  await resetAdminLockout();
  app = await buildApp();
  await app.ready();
});

afterAll(async () => {
  await app.close();
  // Restaura el estado sembrado: los pasos negativos dejan el contador en 3
  // (bloqueado). Lo limpiamos para no romper otras suites/usos de la BD.
  await resetAdminLockout();
});

describe("flujo de autenticación (integración, BD real)", () => {
  it("1. login feliz devuelve kind 'tenants' con 3 empresas y ticket", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/login",
      payload: CREDS,
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.kind).toBe("tenants");
    expect(typeof body.ticket).toBe("string");
    expect(body.ticket.length).toBeGreaterThan(0);
    expect(Array.isArray(body.tenants)).toBe(true);
    expect(body.tenants).toHaveLength(3);

    const names = body.tenants.map((t: { name: string }) => t.name).sort();
    expect(names).toEqual(["base", "demo", "platform"]);

    ticket = body.ticket;
    platformId = body.tenants.find((t: { name: string }) => t.name === "platform").id;
    demoId = body.tenants.find((t: { name: string }) => t.name === "demo").id;
    expect(platformId).toBeTruthy();
    expect(demoId).toBeTruthy();
  });

  it("2. crear sesión con ticket + empresa 'platform' devuelve access, 26 permisos y cookie httpOnly", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/sessions",
      payload: { ticket, customerId: platformId },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(typeof body.accessToken).toBe("string");
    expect(body.accessToken.length).toBeGreaterThan(0);
    expect(body.user.name).toBe("Staff de Plataforma");
    expect(typeof body.user.email).toBe("string");
    expect(body.tenant.name).toBe("platform");
    expect(Array.isArray(body.permissions)).toBe(true);
    expect(body.permissions).toHaveLength(26);

    const cookie = readRefreshCookie(res);
    expect(cookie.httpOnly).toBe(true);
    expect(cookie.value.length).toBeGreaterThan(0);

    refreshCookie = cookie.value;
    accessToken = body.accessToken;
  });

  it("3. verify con Bearer válido devuelve valid:true y claims completos", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/sessions/verify",
      headers: { authorization: `Bearer ${accessToken}` },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.valid).toBe(true);
    expect(body.claims).not.toBeNull();
    for (const claim of ["sub", "acu", "customerId", "appId", "sid"]) {
      expect(typeof body.claims[claim]).toBe("string");
      expect(body.claims[claim].length).toBeGreaterThan(0);
    }
    // El customerId del token debe corresponder a la empresa 'platform'.
    expect(body.claims.customerId).toBe(platformId);
  });

  it("4. refresh con la cookie rota el token y mantiene 26 permisos", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/sessions/refresh",
      cookies: { auth_refresh: refreshCookie },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(typeof body.accessToken).toBe("string");
    expect(body.accessToken.length).toBeGreaterThan(0);
    expect(body.permissions).toHaveLength(26);
    expect(body.tenant.name).toBe("platform");

    // Rotación: la cookie cambia; el token viejo ya no es el vigente.
    const rotated = readRefreshCookie(res);
    expect(rotated.value).not.toBe(refreshCookie);
    refreshCookie = rotated.value;
    accessToken = body.accessToken;
  });

  it("5. switch a 'demo' con access vigente devuelve la sesión en la nueva empresa", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/sessions/switch",
      headers: { authorization: `Bearer ${accessToken}` },
      cookies: { auth_refresh: refreshCookie },
      payload: { customerId: demoId },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.tenant.name).toBe("demo");
    expect(body.tenant.id).toBe(demoId);
    expect(typeof body.accessToken).toBe("string");

    const rotated = readRefreshCookie(res);
    refreshCookie = rotated.value;
    accessToken = body.accessToken;
  });

  it("6. logout (DELETE /auth/sessions/current) responde 204", async () => {
    const res = await app.inject({
      method: "DELETE",
      url: "/auth/sessions/current",
      cookies: { auth_refresh: refreshCookie },
    });

    expect(res.statusCode).toBe(204);
  });

  it("7. opacidad: password incorrecto y usuario inexistente son indistinguibles", async () => {
    const wrongPassword = await app.inject({
      method: "POST",
      url: "/auth/login",
      payload: { ...CREDS, password: "PasswordIncorrecto!", deviceIdentifier: "vitest-opaque-1" },
    });
    const noSuchUser = await app.inject({
      method: "POST",
      url: "/auth/login",
      payload: {
        ...CREDS,
        identifier: "no-existe-este-usuario",
        password: "Cualquiera123!",
        deviceIdentifier: "vitest-opaque-2",
      },
    });

    expect(wrongPassword.statusCode).toBe(401);
    expect(noSuchUser.statusCode).toBe(401);

    const b1 = wrongPassword.json();
    const b2 = noSuchUser.json();
    expect(b1.kind).toBe("invalid");
    expect(b2.kind).toBe("invalid");
    expect(b1.message.code).toBe("ERR_LOGIN_INVALID");
    // Uniformidad total: mismo código, mismo status, mismo cuerpo.
    expect(b2.message.code).toBe(b1.message.code);
    expect(noSuchUser.statusCode).toBe(wrongPassword.statusCode);
    expect(b2).toEqual(b1);
  });

  it("8. JWKS expone claves públicas Ed25519 (OKP/Ed25519) con los miembros JWK", async () => {
    const res = await app.inject({ method: "GET", url: "/auth/.well-known/keys" });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(Array.isArray(body.keys)).toBe(true);
    expect(body.keys.length).toBeGreaterThan(0);
    for (const jwk of body.keys) {
      for (const member of ["kty", "crv", "x", "kid", "use", "alg", "appCode"]) {
        expect(typeof jwk[member]).toBe("string");
        expect(jwk[member].length).toBeGreaterThan(0);
      }
      expect(jwk.kty).toBe("OKP");
      expect(jwk.crv).toBe("Ed25519");
    }
  });

  it("9. i18n: el mensaje de login inválido cambia con Accept-Language", async () => {
    const en = await app.inject({
      method: "POST",
      url: "/auth/login",
      headers: { "accept-language": "en" },
      payload: { ...CREDS, password: "Malo123!", deviceIdentifier: "vitest-i18n-en" },
    });
    const es = await app.inject({
      method: "POST",
      url: "/auth/login",
      headers: { "accept-language": "es" },
      payload: { ...CREDS, password: "Malo123!", deviceIdentifier: "vitest-i18n-es" },
    });

    expect(en.statusCode).toBe(401);
    expect(es.statusCode).toBe(401);
    const mEn = en.json().message;
    const mEs = es.json().message;
    // Mismo código (opacidad), pero texto para el cliente distinto por idioma.
    expect(mEn.code).toBe("ERR_LOGIN_INVALID");
    expect(mEs.code).toBe("ERR_LOGIN_INVALID");
    expect(mEs.messageForClient).not.toBe(mEn.messageForClient);
    expect(mEs.messageForClient.length).toBeGreaterThan(0);
  });
});
