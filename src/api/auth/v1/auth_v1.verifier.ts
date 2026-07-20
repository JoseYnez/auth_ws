import { Verifiers as V } from "structure-verifier";
import { E164_PATTERN } from "../../../core/otp_sender/masking";

// Política de contraseñas de la plataforma (aplicada en confirm/change):
// longitud mínima 12, máxima 256 (argon2id no necesita más restricciones).
const newPasswordV = new V.StringNotNull({ minLength: 12, maxLength: 256 });

// appCode: identifica la app cliente. Charset restringido porque el valor
// nombra la cookie de refresh (`auth_refresh__<appCode>`): solo token-chars
// seguros — sin ';', '=', espacios ni caracteres de control.
const appCodeV = new V.StringNotNull({
  minLength: 1,
  maxLength: 64,
  regex: /^[A-Za-z0-9._-]+$/u,
});

export const loginV1V = new V.ObjectNotNull(
  {
    appCode: appCodeV,
    identifier: new V.StringNotNull({ minLength: 1, maxLength: 320 }),
    password: new V.StringNotNull({ minLength: 1, maxLength: 256 }),
    deviceIdentifier: new V.StringNotNull({ minLength: 1, maxLength: 128 }),
    deviceName: new V.String({ maxLength: 128 }),
  },
  { strictMode: true },
);

export const twoFactorV1V = new V.ObjectNotNull(
  {
    ticket: new V.StringNotNull({ minLength: 1, maxLength: 4096 }),
    // 6 dígitos (TOTP o código OTP de canal) o un código de recuperación (8-32)
    code: new V.StringNotNull({ minLength: 6, maxLength: 32 }).trim(),
  },
  { strictMode: true },
);

/** Reenvío del código 2FA de canal durante el login (método sms/email/whatsapp). */
export const twoFactorResendV1V = new V.ObjectNotNull(
  {
    ticket: new V.StringNotNull({ minLength: 1, maxLength: 4096 }),
  },
  { strictMode: true },
);

export const changePasswordV1V = new V.ObjectNotNull(
  {
    ticket: new V.StringNotNull({ minLength: 1, maxLength: 4096 }),
    newPassword: newPasswordV,
  },
  { strictMode: true },
);

export const createSessionV1V = new V.ObjectNotNull(
  {
    ticket: new V.StringNotNull({ minLength: 1, maxLength: 4096 }),
    customerId: new V.UUIDNotNull(),
  },
  { strictMode: true },
);

// refresh/switch/logout llevan el appCode SOLO para seleccionar qué cookie de
// refresh leer/escribir (una por app); la autoridad sigue siendo la sesión.
export const refreshSessionV1V = new V.ObjectNotNull(
  {
    appCode: appCodeV,
  },
  { strictMode: true },
);

export const switchSessionV1V = new V.ObjectNotNull(
  {
    appCode: appCodeV,
    customerId: new V.UUIDNotNull(),
  },
  { strictMode: true },
);

/** DELETE /auth/sessions/current lleva el appCode por querystring (DELETE sin body). */
export const logoutQueryV1V = new V.ObjectNotNull(
  {
    appCode: appCodeV,
  },
  { strictMode: true },
);

export const passwordResetRequestV1V = new V.ObjectNotNull(
  {
    identifier: new V.StringNotNull({ minLength: 1, maxLength: 320 }),
  },
  { strictMode: true },
);

export const passwordResetConfirmV1V = new V.ObjectNotNull(
  {
    token: new V.StringNotNull({ minLength: 1, maxLength: 512 }),
    newPassword: newPasswordV,
  },
  { strictMode: true },
);

// --- Onboarding: aceptación de invitación + enrolamiento de 2FA (§4.2) ---

export const invitationAcceptV1V = new V.ObjectNotNull(
  {
    token: new V.StringNotNull({ minLength: 1, maxLength: 512 }),
    newPassword: newPasswordV,
  },
  { strictMode: true },
);

export const twoFactorEnrollV1V = new V.ObjectNotNull(
  {
    enrollmentTicket: new V.StringNotNull({ minLength: 1, maxLength: 4096 }),
    // Método 2FA elegido (2FA multicanal): totp mantiene el flujo clásico;
    // los canales envían un código OTP al contacto vinculado.
    method: new V.StringNotNull({ in: ["totp", "sms", "email", "whatsapp"] }),
    // Teléfono E.164 (solo sms/whatsapp; si falta se usa el registrado en BD).
    phone: new V.String({ minLength: 8, maxLength: 16, regex: E164_PATTERN }),
  },
  { strictMode: true },
);

/** Reenvío del código OTP durante el enrolamiento de un método de canal. */
export const twoFactorEnrollResendV1V = new V.ObjectNotNull(
  {
    enrollmentTicket: new V.StringNotNull({ minLength: 1, maxLength: 4096 }),
  },
  { strictMode: true },
);

/** Respuesta de los endpoints de reenvío (login y enrolamiento). */
export const twoFactorResendResponseV1V = new V.ObjectNotNull({
  destination: new V.StringNotNull(),
  remaining: new V.NumberNotNull(),
  cooldownSeconds: new V.NumberNotNull(),
});

export const twoFactorConfirmV1V = new V.ObjectNotNull(
  {
    enrollmentTicket: new V.StringNotNull({ minLength: 1, maxLength: 4096 }),
    code: new V.StringNotNull({ minLength: 6, maxLength: 32 }).trim(),
  },
  { strictMode: true },
);

// Respuesta del paso enroll: material que se muestra UNA vez al usuario (secreto
// base32, URI otpauth para el QR, y los códigos de recuperación crudos).
export const twoFactorEnrollResponseV1V = new V.ObjectNotNull({
  secret: new V.StringNotNull(),
  otpauthUri: new V.StringNotNull(),
  recoveryCodes: new V.ArrayNotNull(new V.StringNotNull()),
});

// Respuesta de sesión (crear / refresh / switch) — contrato §2.2 del raíz.
// Se declara para que el serializer garantice que NUNCA se filtre un campo
// no contratado (hashes, claves, ids internos).
const tenantV = new V.ObjectNotNull({
  id: new V.UUIDNotNull(),
  name: new V.StringNotNull(),
});

export const sessionResponseV1V = new V.ObjectNotNull({
  accessToken: new V.StringNotNull(),
  expiresIn: new V.NumberNotNull(),
  user: new V.ObjectNotNull({
    id: new V.UUIDNotNull(),
    name: new V.StringNotNull(),
    email: new V.StringNotNull(),
  }),
  tenant: tenantV,
  tenants: new V.ArrayNotNull(tenantV),
  permissions: new V.ArrayNotNull(new V.StringNotNull()),
});

/** Respuesta opaca de fallo en endpoints de sesión (401). */
export const invalidResponseV1V = new V.ObjectNotNull({
  error: new V.StringNotNull(),
});

// Permisos efectivos frescos de la sesión (GET /auth/sessions/current/permissions,
// decisión #22). Mismo formato que `sessionResponseV1V.permissions`: lista plana
// de códigos canónicos.
export const sessionPermissionsResponseV1V = new V.ObjectNotNull({
  permissions: new V.ArrayNotNull(new V.StringNotNull()),
});

// JWKS público (GET /auth/.well-known/keys): claves públicas Ed25519 en formato
// JWK (RFC 7517 / 8037). Se declara la respuesta para no filtrar nunca material
// privado; `x` es la clave pública (no secreta). `appCode` es un miembro extra.
export const jwksResponseV1V = new V.ObjectNotNull({
  keys: new V.ArrayNotNull(
    new V.ObjectNotNull({
      kty: new V.StringNotNull(),
      crv: new V.StringNotNull(),
      x: new V.StringNotNull(),
      use: new V.StringNotNull(),
      alg: new V.StringNotNull(),
      kid: new V.StringNotNull(),
      appCode: new V.StringNotNull(),
    }),
  ),
});

// Introspección de access token (endpoint de prueba POST /auth/sessions/verify).
// `claims` solo aparece cuando `valid` es true; se declara opcional para que el
// serializer no exija el objeto en el caso inválido y nunca filtre campos extra.
export const verifyTokenResponseV1V = new V.ObjectNotNull({
  valid: new V.BooleanNotNull(),
  claims: new V.Object({
    sub: new V.UUIDNotNull(),
    acu: new V.UUIDNotNull(),
    customerId: new V.UUIDNotNull(),
    appId: new V.UUIDNotNull(),
    sid: new V.UUIDNotNull(),
    issuedAt: new V.NumberNotNull(),
    expiresAt: new V.NumberNotNull(),
  }),
});

// Los endpoints con respuesta de tipo unión (login / two-factor /
// change-password devuelven kinds distintos) no declaran response verifier:
// structure-verifier no modela uniones discriminadas. El controller es la
// única fuente de esos objetos y no maneja datos sensibles en ellos.
