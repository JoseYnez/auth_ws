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

import { createHmac } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { signEnrollmentTicket } from "../src/core/jwt/enrollment_ticket";
import { drainMailOutbox } from "../src/core/mailer/mailer";
import { drainOtpOutbox } from "../src/core/otp_sender/otp_sender";
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

/**
 * Ejecuta SQL de mantenimiento contra la BD de prueba como role_owner con
 * contexto de auditoría (mismo patrón que resetAdminLockout).
 */
async function adminDb<T>(fn: (client: Client) => Promise<T>): Promise<T> {
  const client = new Client({ connectionString: ADMIN_DSN });
  await client.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET ROLE role_owner");
    await client.query("SELECT set_config('audit.app_name', 'test', true)");
    await client.query("SELECT set_config('audit.action', 'test_maintenance', true)");
    const sys = await client.query("SELECT id FROM auth.users WHERE username = 'system'");
    await client.query("SELECT set_config('audit.user_id', $1, true)", [sys.rows[0].id]);
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    await client.end();
  }
}

/** Desactiva y limpia todo el 2FA del admin (deja el seed como al inicio). */
async function resetAdminTwoFactor(): Promise<void> {
  await adminDb(async (client) => {
    await client.query(
      `UPDATE auth.users
          SET two_factor_enabled = false, two_factor_method = NULL,
              phone = NULL, phone_verified_at = NULL
        WHERE username = 'admin'`,
    );
    await client.query(
      `UPDATE auth.user_two_factor_secrets s
          SET status = 'deleted'
         FROM auth.users u
        WHERE s.user_id = u.id AND u.username = 'admin' AND s.status = 'active'`,
    );
    await client.query(
      `UPDATE auth.user_two_factor_recovery_codes r
          SET status = 'deleted'
         FROM auth.users u
        WHERE r.user_id = u.id AND u.username = 'admin' AND r.status = 'active'`,
    );
    await client.query(
      `DELETE FROM auth.user_verification_tokens t
        USING auth.users u
        WHERE t.user_id = u.id AND u.username = 'admin'
          AND t.purpose IN ('two_factor_sms_challenge', 'two_factor_email_challenge', 'two_factor_whatsapp_challenge')`,
    );
  });
}

// --- TOTP de referencia para los tests (RFC 6238, igual que src/core/crypto/totp) ---

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32DecodeForTest(input: string): Buffer {
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const char of input.toUpperCase().replace(/=+$/u, "")) {
    value = (value << 5) | BASE32_ALPHABET.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** Código TOTP del step actual + offset (offset ±1 queda dentro de la ventana). */
function totpCodeAt(secretBase32: string, stepOffset: number): string {
  const step = Math.floor(Date.now() / 1000 / 30) + stepOffset;
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const digest = createHmac("sha1", base32DecodeForTest(secretBase32)).update(counter).digest();
  const offset = (digest[digest.length - 1] ?? 0) & 0x0f;
  const code =
    (((digest[offset] ?? 0) & 0x7f) << 24) |
    (((digest[offset + 1] ?? 0) & 0xff) << 16) |
    (((digest[offset + 2] ?? 0) & 0xff) << 8) |
    ((digest[offset + 3] ?? 0) & 0xff);
  return String(code % 10 ** 6).padStart(6, "0");
}

/** Login hasta el paso two-factor; devuelve el body de la respuesta. */
async function loginToTwoFactor(deviceSuffix: string) {
  const res = await app.inject({
    method: "POST",
    url: "/auth/login",
    payload: { ...CREDS, deviceIdentifier: `vitest-2fa-${deviceSuffix}` },
  });
  expect(res.statusCode).toBe(200);
  const body = res.json();
  expect(body.kind).toBe("two-factor");
  return body;
}

// Cookie de refresh POR APP: auth_refresh__<appCode> (contrato §2.2).
const REFRESH_COOKIE = "auth_refresh__admin-app";

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
  path: string | undefined;
} {
  const cookie = res.cookies.find((c) => c.name === REFRESH_COOKIE);
  if (cookie === undefined) {
    throw new Error(`La respuesta no trae cookie ${REFRESH_COOKIE}`);
  }
  return { value: cookie.value, httpOnly: cookie.httpOnly === true, path: cookie.path };
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
    expect(cookie.path).toBe("/auth/sessions");
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
      cookies: { [REFRESH_COOKIE]: refreshCookie },
      payload: { appCode: "admin-app" },
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
      cookies: { [REFRESH_COOKIE]: refreshCookie },
      payload: { appCode: "admin-app", customerId: demoId },
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
      url: "/auth/sessions/current?appCode=admin-app",
      cookies: { [REFRESH_COOKIE]: refreshCookie },
    });

    expect(res.statusCode).toBe(204);
  });

  it("6b. refresh sin cookie de la app responde 401 opaco y limpia esa cookie", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/sessions/refresh",
      payload: { appCode: "admin-app" },
    });

    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ error: "invalid" });
    // Set-Cookie de borrado de la cookie de ESTA app.
    const cleared = res.cookies.find((c) => c.name === REFRESH_COOKIE);
    expect(cleared?.value).toBe("");
  });

  it("6c. appCode con charset inválido para nombre de cookie responde 400 (verifier)", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/sessions/refresh",
      payload: { appCode: "bad code;" },
    });

    expect(res.statusCode).toBe(400);
  });

  it("6d. la cookie legacy auth_refresh jamás se lee: refresh con solo la legacy responde 401", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/sessions/refresh",
      cookies: { auth_refresh: refreshCookie },
      payload: { appCode: "admin-app" },
    });

    expect(res.statusCode).toBe(401);
  });

  it("6e. aislamiento entre apps: pedir otra app no toca la cookie de admin-app", async () => {
    // Nueva sesión de admin-app (la del paso 6 quedó revocada).
    const login = await app.inject({
      method: "POST",
      url: "/auth/login",
      payload: { ...CREDS, deviceIdentifier: "vitest-isolation" },
    });
    expect(login.statusCode).toBe(200);
    const session = await app.inject({
      method: "POST",
      url: "/auth/sessions",
      payload: { ticket: login.json().ticket, customerId: platformId },
    });
    expect(session.statusCode).toBe(200);
    const adminCookie = readRefreshCookie(session).value;

    // Refresh pidiendo OTRA app con la cookie de admin-app presente en el
    // navegador: no hay cookie auth_refresh__other-app → 401, sin tocar la
    // sesión de admin-app.
    const other = await app.inject({
      method: "POST",
      url: "/auth/sessions/refresh",
      cookies: { [REFRESH_COOKIE]: adminCookie },
      payload: { appCode: "other-app" },
    });
    expect(other.statusCode).toBe(401);
    expect(other.cookies.find((c) => c.name === REFRESH_COOKIE)).toBeUndefined();

    // La sesión de admin-app sigue viva y refrescable.
    const still = await app.inject({
      method: "POST",
      url: "/auth/sessions/refresh",
      cookies: { [REFRESH_COOKIE]: adminCookie },
      payload: { appCode: "admin-app" },
    });
    expect(still.statusCode).toBe(200);
    expect(still.json().tenant.name).toBe("platform");

    // Limpieza: revocar esta sesión para no dejar estado extra.
    const rotated = readRefreshCookie(still).value;
    const bye = await app.inject({
      method: "DELETE",
      url: "/auth/sessions/current?appCode=admin-app",
      cookies: { [REFRESH_COOKIE]: rotated },
    });
    expect(bye.statusCode).toBe(204);
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

describe("2FA multicanal (whatsapp/sms/email + regresión TOTP)", () => {
  const TEST_PHONE = "+5215512345678";
  let adminId = "";
  let adminEmail = "";
  let recoveryCodes: string[] = [];

  beforeAll(async () => {
    // Los tests de opacidad/i18n (7 y 9) dejan al admin bloqueado por
    // intentos fallidos: esta suite necesita volver a loguear.
    await resetAdminLockout();
    const row = await adminDb((client) =>
      client.query("SELECT id, email FROM auth.users WHERE username = 'admin'"),
    );
    adminId = row.rows[0].id;
    adminEmail = row.rows[0].email;
    await resetAdminTwoFactor();
    drainOtpOutbox();
    drainMailOutbox();
  });

  afterAll(async () => {
    // El resto de suites y corridas futuras esperan al admin SIN 2FA.
    await resetAdminTwoFactor();
  });

  it("10. enroll whatsapp: destino enmascarado, recovery codes y código en el outbox", async () => {
    const enrollmentTicket = await signEnrollmentTicket(adminId, adminEmail);
    const res = await app.inject({
      method: "POST",
      url: "/auth/two-factor/enroll",
      payload: { enrollmentTicket, method: "whatsapp", phone: TEST_PHONE },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.method).toBe("whatsapp");
    expect(body.destination).toBe("+52•••5678");
    expect(body.cooldownSeconds).toBe(60);
    expect(Array.isArray(body.recoveryCodes)).toBe(true);
    expect(body.recoveryCodes.length).toBeGreaterThan(0);
    recoveryCodes = body.recoveryCodes;

    const sent = drainOtpOutbox();
    expect(sent).toHaveLength(1);
    expect(sent[0]?.channel).toBe("whatsapp");
    expect(sent[0]?.to).toBe(TEST_PHONE);
    expect(sent[0]?.code).toMatch(/^\d{6}$/u);

    // Confirm con código incorrecto: 400 reintentable, no activa nada.
    const wrongCode = sent[0]!.code === "000000" ? "000001" : "000000";
    const bad = await app.inject({
      method: "POST",
      url: "/auth/two-factor/confirm",
      payload: { enrollmentTicket, code: wrongCode },
    });
    expect(bad.statusCode).toBe(400);

    // Confirm con el código real: activa el método y sella el teléfono.
    const ok = await app.inject({
      method: "POST",
      url: "/auth/two-factor/confirm",
      payload: { enrollmentTicket, code: sent[0]!.code },
    });
    expect(ok.statusCode).toBe(200);
    expect(ok.json().kind).toBe("done");

    const state = await adminDb((client) =>
      client.query(
        `SELECT two_factor_enabled, two_factor_method, phone, phone_verified_at
           FROM auth.users WHERE id = $1`,
        [adminId],
      ),
    );
    expect(state.rows[0].two_factor_enabled).toBe(true);
    expect(state.rows[0].two_factor_method).toBe("whatsapp");
    expect(state.rows[0].phone).toBe(TEST_PHONE);
    expect(state.rows[0].phone_verified_at).not.toBeNull();
  });

  it("11. login por whatsapp: envía el código, lo canjea y entrega tenants", async () => {
    const step = await loginToTwoFactor("wa-login");
    expect(step.method).toBe("whatsapp");
    expect(step.destination).toBe("+52•••5678");

    const sent = drainOtpOutbox();
    expect(sent).toHaveLength(1);

    const res = await app.inject({
      method: "POST",
      url: "/auth/two-factor",
      payload: { ticket: step.ticket, code: sent[0]!.code },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().kind).toBe("tenants");
    expect(res.json().tenants).toHaveLength(3);
  });

  it("12. resend: el código nuevo invalida el anterior y el cooldown responde 429", async () => {
    const step = await loginToTwoFactor("wa-resend");
    const first = drainOtpOutbox();
    expect(first).toHaveLength(1);

    const resend = await app.inject({
      method: "POST",
      url: "/auth/two-factor/resend",
      payload: { ticket: step.ticket },
    });
    expect(resend.statusCode).toBe(200);
    expect(resend.json().destination).toBe("+52•••5678");
    expect(resend.json().remaining).toBe(2);
    expect(resend.json().cooldownSeconds).toBe(60);

    const second = drainOtpOutbox();
    expect(second).toHaveLength(1);
    expect(second[0]!.code).not.toBe(first[0]!.code);

    // Reenvío inmediato: cooldown de 60 s → 429.
    const tooSoon = await app.inject({
      method: "POST",
      url: "/auth/two-factor/resend",
      payload: { ticket: step.ticket },
    });
    expect(tooSoon.statusCode).toBe(429);
    expect(tooSoon.json().message.code).toBe("ERR_2FA_RESEND_COOLDOWN");

    // El código VIEJO ya no vale (la emisión borró su challenge)…
    const stale = await app.inject({
      method: "POST",
      url: "/auth/two-factor",
      payload: { ticket: step.ticket, code: first[0]!.code },
    });
    expect(stale.statusCode).toBe(400);
    expect(stale.json().message.code).toBe("ERR_2FA_INVALID_CODE");

    // …y el NUEVO sí.
    const fresh = await app.inject({
      method: "POST",
      url: "/auth/two-factor",
      payload: { ticket: step.ticket, code: second[0]!.code },
    });
    expect(fresh.statusCode).toBe(200);
    expect(fresh.json().kind).toBe("tenants");
  });

  it("13. un código de recuperación sigue funcionando con método de canal", async () => {
    const step = await loginToTwoFactor("wa-recovery");
    drainOtpOutbox();

    const res = await app.inject({
      method: "POST",
      url: "/auth/two-factor",
      payload: { ticket: step.ticket, code: recoveryCodes[0] },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().kind).toBe("tenants");
  });

  it("14. canal email: el código viaja por el mailer y sella el flujo completo", async () => {
    await resetAdminTwoFactor();
    drainMailOutbox();

    const enrollmentTicket = await signEnrollmentTicket(adminId, adminEmail);
    const enroll = await app.inject({
      method: "POST",
      url: "/auth/two-factor/enroll",
      payload: { enrollmentTicket, method: "email" },
    });
    expect(enroll.statusCode).toBe(200);
    expect(enroll.json().method).toBe("email");
    expect(enroll.json().destination).toBe(`${adminEmail[0]}•••@${adminEmail.split("@")[1]}`);

    const mails = drainMailOutbox();
    expect(mails).toHaveLength(1);
    expect(mails[0]?.to).toBe(adminEmail);
    const code = /\b(\d{6})\b/u.exec(mails[0]!.text)?.[1];
    expect(code).toBeDefined();

    const confirm = await app.inject({
      method: "POST",
      url: "/auth/two-factor/confirm",
      payload: { enrollmentTicket, code },
    });
    expect(confirm.statusCode).toBe(200);

    const step = await loginToTwoFactor("email-login");
    expect(step.method).toBe("email");
    const loginMails = drainMailOutbox();
    expect(loginMails).toHaveLength(1);
    const loginCode = /\b(\d{6})\b/u.exec(loginMails[0]!.text)?.[1];

    const res = await app.inject({
      method: "POST",
      url: "/auth/two-factor",
      payload: { ticket: step.ticket, code: loginCode },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().kind).toBe("tenants");
  });

  it("15. regresión TOTP: enroll + confirm + login intactos", async () => {
    await resetAdminTwoFactor();

    const enrollmentTicket = await signEnrollmentTicket(adminId, adminEmail);
    const enroll = await app.inject({
      method: "POST",
      url: "/auth/two-factor/enroll",
      payload: { enrollmentTicket, method: "totp" },
    });
    expect(enroll.statusCode).toBe(200);
    const body = enroll.json();
    expect(body.method).toBe("totp");
    expect(typeof body.secret).toBe("string");
    expect(body.otpauthUri).toContain("otpauth://totp/");

    const confirm = await app.inject({
      method: "POST",
      url: "/auth/two-factor/confirm",
      payload: { enrollmentTicket, code: totpCodeAt(body.secret, 0) },
    });
    expect(confirm.statusCode).toBe(200);

    const step = await loginToTwoFactor("totp-login");
    expect(step.method).toBe("totp");
    expect(step.destination).toBeUndefined();
    // El reenvío no aplica a TOTP.
    const resend = await app.inject({
      method: "POST",
      url: "/auth/two-factor/resend",
      payload: { ticket: step.ticket },
    });
    expect(resend.statusCode).toBe(400);
    expect(resend.json().message.code).toBe("ERR_2FA_METHOD_NOT_RESENDABLE");

    // Anti-replay: el step de la confirmación no se reutiliza — usar el
    // siguiente (dentro de la ventana ±1 de matchTotpStep).
    const res = await app.inject({
      method: "POST",
      url: "/auth/two-factor",
      payload: { ticket: step.ticket, code: totpCodeAt(body.secret, 1) },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().kind).toBe("tenants");
  });
});
