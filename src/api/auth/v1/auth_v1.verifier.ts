import { Verifiers as V } from "structure-verifier";

// Política de contraseñas de la plataforma (aplicada en confirm/change):
// longitud mínima 12, máxima 256 (argon2id no necesita más restricciones).
const newPasswordV = new V.StringNotNull({ minLength: 12, maxLength: 256 });

export const loginV1V = new V.ObjectNotNull(
  {
    appCode: new V.StringNotNull({ minLength: 1, maxLength: 64 }),
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
    // 6 dígitos TOTP o un código de recuperación (8-32 chars)
    code: new V.StringNotNull({ minLength: 6, maxLength: 32 }).trim(),
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

export const switchSessionV1V = new V.ObjectNotNull(
  {
    customerId: new V.UUIDNotNull(),
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

// Los endpoints con respuesta de tipo unión (login / two-factor /
// change-password devuelven kinds distintos) no declaran response verifier:
// structure-verifier no modela uniones discriminadas. El controller es la
// única fuente de esos objetos y no maneja datos sensibles en ellos.
