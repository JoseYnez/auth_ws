import { createPublicKey } from "node:crypto";
import type { InferType } from "structure-verifier";
import type { AuditContext } from "../../../core/audit/audit_context";
import { withTransaction, type TxClient } from "../../../core/db/with_transaction";
import { decryptText, encryptText } from "../../../core/crypto/encryption";
import { hashPassword, verifyAgainstDummy, verifyPassword } from "../../../core/crypto/password";
import { generateRecoveryCodes, normalizeRecoveryCode } from "../../../core/crypto/recovery_codes";
import { generateOpaqueToken, sha256Hex } from "../../../core/crypto/token";
import {
  buildOtpauthUri,
  generateTotpSecretBase32,
  matchTotpStep,
} from "../../../core/crypto/totp";
import { signEnrollmentTicket, verifyEnrollmentTicket } from "../../../core/jwt/enrollment_ticket";
import {
  buildPasswordResetEmail,
  buildTwoFactorCodeEmail,
  getMailer,
} from "../../../core/mailer/mailer";
import { maskEmail, maskPhone } from "../../../core/otp_sender/masking";
import {
  CHALLENGE_PURPOSE_BY_METHOD,
  CHALLENGE_TTL_SECONDS,
  generateOtpCode,
  hashOtpCode,
  type ChannelMethod,
} from "../../../core/otp_sender/otp_code";
import { getOtpSender } from "../../../core/otp_sender/otp_sender";
import {
  RESEND_COOLDOWN_SECONDS,
  tryConsumeResend,
} from "../../../core/security/two_factor_resend_throttle";
import {
  clearTwoFactorAttempts,
  isTwoFactorLocked,
  registerFailedTwoFactor,
} from "../../../core/security/two_factor_attempts";
import { tryAcceptTotpStep } from "../../../core/security/totp_replay";
import {
  peekAccessTokenClaims,
  signAccessToken,
  verifyAccessToken,
  type VerifiedAccessToken,
} from "../../../core/jwt/access_token";
import { getSigningKey } from "../../../core/jwt/signing_keys";
import { signTicket, verifyTicket, type TicketPayload } from "../../../core/jwt/ticket";
import {
  authRepository as repo,
  type SessionPayloadOk,
  type Tenant,
  type TwoFactorMethod,
} from "./auth_v1.repository";
import type {
  changePasswordV1V,
  createSessionV1V,
  invitationAcceptV1V,
  loginV1V,
  passwordResetConfirmV1V,
  passwordResetRequestV1V,
  switchSessionV1V,
  twoFactorConfirmV1V,
  twoFactorEnrollResendV1V,
  twoFactorEnrollV1V,
  twoFactorResendV1V,
  twoFactorV1V,
} from "./auth_v1.verifier";
import { extractLanguage, getMessageByCode } from "./auth_v1.messages";

// Tipos del contrato §2.2 (espejo de AuthGateway en base_project)

export type LoginStepResult =
  | {
      kind: "invalid";
      message?: {
        code: string;
        messageForClient: string;
        messageForDeveloper: string;
        httpStatusCode: number;
      };
    }
  | {
      kind: "two-factor";
      ticket: string;
      method: TwoFactorMethod;
      /**
       * Destino ENMASCARADO del código (solo métodos de canal): a dónde se
       * envió. `null` = el envío no fue posible (invariante rota: método de
       * canal sin contacto); el usuario aún puede usar un código de
       * recuperación. Se omite para totp.
       */
      destination?: string | null;
    }
  | { kind: "change-password"; ticket: string }
  | { kind: "tenants"; ticket: string; tenants: Tenant[] };

export interface SessionResponse {
  accessToken: string;
  expiresIn: number; // segundos de vida del access token
  user: { id: string; name: string; email: string };
  tenant: Tenant;
  tenants: Tenant[];
  permissions: string[];
}

export type SessionResult =
  | {
      ok: true;
      /** App cuya cookie de refresh debe escribirse: del ticket en create, del request en refresh/switch. */
      appCode: string;
      session: SessionResponse;
      refreshToken: string;
      refreshTtlMinutes: number;
    }
  | {
      ok: false;
      /** Presente cuando la app del fallo se conoce (permite limpiar SOLO su cookie). */
      appCode?: string;
    };

/**
 * Clave pública Ed25519 en formato JWK (RFC 7517 / RFC 8037) para el JWKS de
 * `/auth/.well-known/keys`. `appCode` es un miembro extra (no estándar, los
 * consumidores lo ignoran) para que un resource server identifique su app.
 */
export interface JwkEd25519 {
  kty: string;
  crv: string;
  x: string;
  use: "sig";
  alg: "EdDSA";
  kid: string;
  appCode: string;
}

/** Resultado de introspección de un access token (endpoint de prueba). */
export interface AccessTokenIntrospection {
  valid: boolean;
  claims: {
    sub: string;
    acu: string;
    customerId: string;
    appId: string;
    sid: string;
    issuedAt: number;
    expiresAt: number;
  } | null;
}

const PASSWORD_RESET_TTL_MINUTES = 60;

/**
 * Sentinel interno de `twoFactor`: aborta la transacción cuando un código de
 * recuperación YA quedó consumido pero el canje del jti del ticket falló
 * (ticket replayado o quemado desde otra instancia). El ROLLBACK devuelve el
 * código de recuperación intacto — su burn solo debe COMMITear cuando todo lo
 * demás quedó validado — y el controller responde el mismo
 * `ERR_TICKET_INVALID` opaco que cualquier ticket inválido. No es un error de
 * negocio hacia fuera: jamás sale del controller.
 */
class RecoveryCodeBurnRollback extends Error {
  constructor() {
    super("rollback: recovery code consumido con ticket jti ya canjeado");
  }
}

// Emisor mostrado por las apps authenticator al importar el secreto TOTP.
const OTP_ISSUER = "Plataforma";

/** Idioma del catálogo → locale de las plantillas de envío. */
function toLocale(language: string): "en" | "es" {
  return language === "es" ? "es" : "en";
}

/** El valor interno legado `authenticator_app` se normaliza a `totp`. */
function normalizeTwoFactorMethod(method: string | null): TwoFactorMethod {
  return method === "sms" || method === "email" || method === "whatsapp" ? method : "totp";
}

/** Narrowing del método del verifier a método de canal (null = totp). */
function asChannelMethod(value: string): ChannelMethod | null {
  return value === "sms" || value === "email" || value === "whatsapp" ? value : null;
}

/**
 * Envío pendiente del código OTP de canal. Se despacha SOLO tras el COMMIT
 * (patrón de requestPasswordReset): fire-and-forget, sin bloquear la
 * respuesta; el fallo se loggea y el usuario puede pedir reenvío.
 */
interface OtpDelivery {
  readonly method: ChannelMethod;
  readonly email: string;
  readonly phone: string | null;
  readonly code: string;
  readonly locale: "en" | "es";
}

function dispatchOtpDelivery(delivery: OtpDelivery | null): void {
  if (delivery === null) {
    return;
  }
  const task =
    delivery.method === "email"
      ? getMailer().send(buildTwoFactorCodeEmail(delivery.email, delivery.code, delivery.locale))
      : delivery.phone !== null
        ? getOtpSender().send({
            to: delivery.phone,
            code: delivery.code,
            channel: delivery.method,
            locale: delivery.locale,
          })
        : Promise.resolve();
  void task.catch((err: unknown) => {
    console.error("Fallo al enviar código 2FA:", err);
  });
}

/** Contacto del método 2FA activo (de sp_login o fn_get_two_factor_channel_info). */
interface TwoFactorContact {
  readonly method: TwoFactorMethod;
  readonly email: string;
  readonly phone: string | null;
}

/**
 * Paso `two-factor` del flujo (login / change-password): firma el ticket y,
 * para métodos de canal, emite el challenge OTP dentro de la transacción.
 * `destination: null` = invariante rota (método de canal sin contacto): no se
 * envía nada — el usuario aún puede entrar con un código de recuperación y la
 * opacidad no se rompe.
 */
async function prepareTwoFactorStep(
  tx: TxClient,
  base: Pick<TicketPayload, "userId" | "appId" | "appCode" | "deviceIdentifier" | "deviceName">,
  contact: TwoFactorContact,
  language: string,
  ctx: AuditContext,
): Promise<{ step: LoginStepResult; delivery: OtpDelivery | null }> {
  const { ticket } = await signTicket({ ...base, purpose: "two-factor" });
  if (contact.method === "totp") {
    return { step: { kind: "two-factor", ticket, method: "totp" }, delivery: null };
  }

  const method = contact.method;
  const phone = contact.phone;
  if (method !== "email" && phone === null) {
    console.error(`2FA por ${method} sin teléfono registrado: no se envía código`);
    return { step: { kind: "two-factor", ticket, method, destination: null }, delivery: null };
  }

  const code = generateOtpCode();
  const purpose = CHALLENGE_PURPOSE_BY_METHOD[method];
  const issued = await repo.spIssueTwoFactorChallenge(tx, {
    userId: base.userId,
    purpose,
    codeHash: hashOtpCode(base.userId, purpose, code),
    ttlSeconds: CHALLENGE_TTL_SECONDS,
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
  });
  if (!issued.ok) {
    return { step: { kind: "two-factor", ticket, method, destination: null }, delivery: null };
  }

  const destination =
    method === "email" ? maskEmail(contact.email) : phone !== null ? maskPhone(phone) : null;
  return {
    step: { kind: "two-factor", ticket, method, destination },
    delivery: { method, email: contact.email, phone, code, locale: toLocale(language) },
  };
}

/** Resultado de los endpoints de reenvío del código OTP (login y enroll). */
export type TwoFactorResendResult =
  | { kind: "resent"; destination: string; remaining: number; cooldownSeconds: number }
  | InvalidResult;

/** Variante `invalid` con `message` garantizado (para uniones de onboarding). */
interface InvalidResult {
  kind: "invalid";
  message: {
    code: string;
    messageForClient: string;
    messageForDeveloper: string;
    httpStatusCode: number;
  };
}

export type InvitationAcceptResult =
  | { kind: "enroll-2fa"; enrollmentTicket: string }
  | InvalidResult;

export type TwoFactorEnrollResult =
  | {
      kind: "enrolled";
      method: "totp";
      secret: string;
      otpauthUri: string;
      recoveryCodes: string[];
    }
  | {
      kind: "enrolled";
      method: ChannelMethod;
      /** Destino ENMASCARADO al que se envió el código OTP. */
      destination: string;
      recoveryCodes: string[];
      cooldownSeconds: number;
    }
  | InvalidResult;

export type TwoFactorConfirmResult = { kind: "done" } | InvalidResult;

function invalidResult(code: string, language: string): InvalidResult {
  const msg = getMessageByCode(code, language);
  return {
    kind: "invalid",
    message: {
      code: msg.code,
      messageForClient: msg.messageForClient,
      messageForDeveloper: msg.messageForDeveloper,
      httpStatusCode: msg.httpStatusCode,
    },
  };
}

/**
 * Emite el access token del par cliente-app y arma la respuesta de sesión a
 * partir del payload de los SPs (crear / refresh / switch comparten esto).
 */
async function buildSessionResult(
  payload: SessionPayloadOk,
  refreshToken: string,
  // El payload de los SPs trae appId pero no appCode: viaja como parámetro
  // desde el dato confiable de cada caso (ticket firmado o cookie leída).
  appCode: string,
): Promise<SessionResult> {
  if (payload.signingKeyEncrypted === null) {
    // Contratación sin clave de firma = error de configuración de la
    // plataforma, no un fallo de negocio: debe verse como 500 en logs.
    throw new Error(
      `customer_apps (${payload.customerId}, ${payload.appId}) sin access_token_signing_key_encrypted`,
    );
  }
  const key = getSigningKey(payload.customerId, payload.appId, payload.signingKeyEncrypted);
  const accessToken = await signAccessToken(
    {
      sub: payload.userId,
      acu: payload.acuId,
      customerId: payload.customerId,
      appId: payload.appId,
      sid: payload.sessionId,
    },
    key,
    payload.accessTokenTtlMinutes,
  );
  return {
    ok: true,
    appCode,
    session: {
      accessToken,
      expiresIn: payload.accessTokenTtlMinutes * 60,
      user: payload.user,
      tenant: payload.tenant,
      tenants: payload.tenants,
      permissions: payload.permissions,
    },
    refreshToken,
    refreshTtlMinutes: payload.refreshTokenTtlMinutes,
  };
}

/**
 * Resultado `invalid` con el `message` (y su `httpStatusCode`) resuelto desde
 * el catálogo. La route aplica ese estatus a la respuesta HTTP (`sendStep`).
 */
function invalidStep(code: string, language: string): LoginStepResult {
  const msg = getMessageByCode(code, language);
  return {
    kind: "invalid",
    message: {
      code: msg.code,
      messageForClient: msg.messageForClient,
      messageForDeveloper: msg.messageForDeveloper,
      httpStatusCode: msg.httpStatusCode,
    },
  };
}

/**
 * Respuesta opaca del login: debe ser IDÉNTICA para credenciales inválidas,
 * usuario inexistente, usuario bloqueado y usuario sin empresas en la app
 * (CLAUDE.md §2 "Respuestas opacas" / §7) — siempre `ERR_LOGIN_INVALID` (401),
 * sin distinguir el motivo.
 */
function invalidLoginResult(language: string): LoginStepResult {
  return invalidStep("ERR_LOGIN_INVALID", language);
}

/** Paso siguiente tras superar credenciales / 2FA / cambio de contraseña. */
async function nextStepTicket(
  base: Pick<TicketPayload, "userId" | "appId" | "appCode" | "deviceIdentifier" | "deviceName">,
  tenants: Tenant[],
  language: string,
): Promise<LoginStepResult> {
  if (tenants.length === 0) {
    // Usuario sin empresas en la app = MISMO cuerpo/estatus opaco que
    // credencial inválida, en cualquier paso del flujo (CLAUDE.md §7).
    return invalidLoginResult(language);
  }
  const { ticket } = await signTicket({ ...base, purpose: "tenants" });
  return { kind: "tenants", ticket, tenants };
}

export const authController = {
  async login(data: InferType<typeof loginV1V>, ctx: AuditContext): Promise<LoginStepResult> {
    const language = extractLanguage(ctx.acceptLanguage);

    // El envío del código OTP de canal se despacha DESPUÉS del commit: si la
    // transacción aborta, el usuario no recibe un código que la BD no conoce.
    const outcome = await withTransaction(
      ctx,
      async (tx): Promise<{ step: LoginStepResult; delivery: OtpDelivery | null }> => {
        const row = await repo.spLogin(tx, data.appCode, data.identifier);

        if (!row.ok) {
          // Igualar tiempos: el "usuario no existe" no debe distinguirse
          // de "contraseña incorrecta" por la latencia.
          await verifyAgainstDummy(data.password);
          return { step: invalidLoginResult(language), delivery: null };
        }

        const verified = await verifyPassword(row.secretHash, data.password);
        await repo.spRegisterLoginAttempt(tx, row.userId, row.appId, verified);
        if (!verified) {
          return { step: invalidLoginResult(language), delivery: null };
        }

        const ticketBase = {
          userId: row.userId,
          appId: row.appId,
          appCode: data.appCode,
          deviceIdentifier: data.deviceIdentifier,
          deviceName: data.deviceName,
        };

        // must_change_secret tiene prioridad: no se emiten empresas ni 2FA
        // hasta completar el cambio (CLAUDE.md raíz §2).
        if (row.mustChangeSecret) {
          const { ticket } = await signTicket({ ...ticketBase, purpose: "change-password" });
          return { step: { kind: "change-password", ticket }, delivery: null };
        }

        if (row.twoFactorEnabled) {
          return prepareTwoFactorStep(
            tx,
            ticketBase,
            {
              method: normalizeTwoFactorMethod(row.twoFactorMethod),
              email: row.twoFactorEmail ?? "",
              phone: row.twoFactorPhone,
            },
            language,
            ctx,
          );
        }

        return { step: await nextStepTicket(ticketBase, row.tenants, language), delivery: null };
      },
    );

    dispatchOtpDelivery(outcome.delivery);
    return outcome.step;
  },

  /**
   * Reenvío del código OTP durante el login (método de canal). Cada reenvío
   * emite un código NUEVO que invalida el anterior (la emisión borra el
   * challenge previo). Throttle por ticket: 3 reenvíos, cooldown 60 s; agotar
   * los reenvíos NO invalida el ticket (el último código y los códigos de
   * recuperación siguen valiendo).
   */
  async twoFactorResend(
    data: InferType<typeof twoFactorResendV1V>,
    ctx: AuditContext,
  ): Promise<TwoFactorResendResult> {
    const language = extractLanguage(ctx.acceptLanguage);
    const ticket = await verifyTicket(data.ticket, "two-factor");
    if (ticket === null) {
      return invalidResult("ERR_TICKET_INVALID", language);
    }

    const jtiHash = sha256Hex(ticket.jti);
    if (isTwoFactorLocked(jtiHash)) {
      return invalidResult("ERR_TICKET_INVALID", language);
    }

    const verdict = tryConsumeResend(jtiHash);
    if (!verdict.ok) {
      return invalidResult(
        verdict.reason === "cooldown" ? "ERR_2FA_RESEND_COOLDOWN" : "ERR_2FA_RESEND_LIMIT",
        language,
      );
    }

    const outcome = await withTransaction(
      ctx,
      async (tx): Promise<{ result: TwoFactorResendResult; delivery: OtpDelivery | null }> => {
        const info = await repo.fnGetTwoFactorChannelInfo(tx, ticket.userId);
        if (info === null) {
          // Sin 2FA activo un ticket two-factor no debería existir: opaco.
          return { result: invalidResult("ERR_TICKET_INVALID", language), delivery: null };
        }
        if (info.method === "totp") {
          return {
            result: invalidResult("ERR_2FA_METHOD_NOT_RESENDABLE", language),
            delivery: null,
          };
        }
        if (info.method !== "email" && info.phone === null) {
          return {
            result: invalidResult("ERR_2FA_METHOD_NOT_RESENDABLE", language),
            delivery: null,
          };
        }

        const code = generateOtpCode();
        const purpose = CHALLENGE_PURPOSE_BY_METHOD[info.method];
        const issued = await repo.spIssueTwoFactorChallenge(tx, {
          userId: ticket.userId,
          purpose,
          codeHash: hashOtpCode(ticket.userId, purpose, code),
          ttlSeconds: CHALLENGE_TTL_SECONDS,
          ipAddress: ctx.ipAddress,
          userAgent: ctx.userAgent,
        });
        if (!issued.ok) {
          return { result: invalidResult("ERR_TICKET_INVALID", language), delivery: null };
        }

        const destination =
          info.method === "email"
            ? maskEmail(info.email)
            : info.phone !== null
              ? maskPhone(info.phone)
              : "•••";
        return {
          result: {
            kind: "resent",
            destination,
            remaining: verdict.remaining,
            cooldownSeconds: RESEND_COOLDOWN_SECONDS,
          },
          delivery: {
            method: info.method,
            email: info.email,
            phone: info.phone,
            code,
            locale: toLocale(language),
          },
        };
      },
    );

    dispatchOtpDelivery(outcome.delivery);
    return outcome.result;
  },

  async twoFactor(
    data: InferType<typeof twoFactorV1V>,
    ctx: AuditContext,
  ): Promise<LoginStepResult> {
    const language = extractLanguage(ctx.acceptLanguage);
    const ticket = await verifyTicket(data.ticket, "two-factor");
    if (ticket === null) {
      return invalidStep("ERR_TICKET_INVALID", language);
    }

    const jtiHash = sha256Hex(ticket.jti);
    // Ticket que ya agotó sus intentos de 2FA (fuerza bruta): tratado como
    // ticket inválido, no como código incorrecto reintentable.
    if (isTwoFactorLocked(jtiHash)) {
      return invalidStep("ERR_TICKET_INVALID", language);
    }

    try {
      return await withTransaction(ctx, async (tx) => {
        let valid = false;
        let recoveryCodeBurned = false;

        if (/^\d{6}$/u.test(data.code)) {
          // Los 6 dígitos se verifican según el MÉTODO del usuario: challenge
          // OTP de canal (sms/email/whatsapp) o TOTP (totp/authenticator_app).
          const info = await repo.fnGetTwoFactorChannelInfo(tx, ticket.userId);
          if (info !== null && info.method !== "totp") {
            const purpose = CHALLENGE_PURPOSE_BY_METHOD[info.method];
            const consumed = await repo.spConsumeTwoFactorChallenge(
              tx,
              ticket.userId,
              purpose,
              hashOtpCode(ticket.userId, purpose, data.code),
            );
            // Código incorrecto y expirado son indistinguibles (opacidad).
            valid = consumed.ok;
          } else {
            const secretEncrypted = await repo.fnGetTwoFactorSecret(tx, ticket.userId);
            if (secretEncrypted !== null) {
              const step = matchTotpStep(decryptText(secretEncrypted), data.code);
              // Anti-replay (RELEASE_PLAN 5.3): un step ya aceptado para este
              // usuario se trata como código incorrecto — respuesta opaca.
              valid = step !== null && tryAcceptTotpStep(ticket.userId, step);
            }
          }
        }

        if (!valid) {
          // Código de recuperación (one-shot; la BD guarda sha256 del código
          // NORMALIZADO — mayúsculas, sin guiones —, igual que el enrolamiento).
          const recovery = await repo.spConsumeRecoveryCode(
            tx,
            ticket.userId,
            sha256Hex(normalizeRecoveryCode(data.code)),
          );
          valid = recovery.ok;
          recoveryCodeBurned = recovery.ok;
        }

        if (!valid) {
          // Código incorrecto: el ticket sigue vivo y se puede reintentar (400)…
          const { locked } = registerFailedTwoFactor(jtiHash, ticket.expiresAt);
          if (locked) {
            // …salvo que se alcance el umbral de intentos: se quema el jti en BD
            // (one-shot) para invalidar el ticket también en el resto del clúster.
            await repo.spConsumeTicketJti(tx, ticket.userId, jtiHash, ticket.expiresAt);
            return invalidStep("ERR_TICKET_INVALID", language);
          }
          return invalidStep("ERR_2FA_INVALID_CODE", language);
        }

        const consumed = await repo.spConsumeTicketJti(
          tx,
          ticket.userId,
          jtiHash,
          ticket.expiresAt,
        );
        if (!consumed.ok) {
          if (recoveryCodeBurned) {
            // El burn del recovery code solo puede COMMITear tras validar todo
            // lo demás: con el jti ya canjeado (replay / quemado en otra
            // instancia) se aborta la transacción para devolver el código.
            throw new RecoveryCodeBurnRollback();
          }
          return invalidStep("ERR_TICKET_INVALID", language);
        }

        clearTwoFactorAttempts(jtiHash);
        const tenants = await repo.fnGetAccessibleTenants(tx, ticket.userId, ticket.appId);
        return nextStepTicket(ticket, tenants, language);
      });
    } catch (err) {
      if (err instanceof RecoveryCodeBurnRollback) {
        return invalidStep("ERR_TICKET_INVALID", language);
      }
      throw err;
    }
  },

  async changePassword(
    data: InferType<typeof changePasswordV1V>,
    ctx: AuditContext,
  ): Promise<LoginStepResult> {
    const language = extractLanguage(ctx.acceptLanguage);
    const ticket = await verifyTicket(data.ticket, "change-password");
    if (ticket === null) {
      return invalidStep("ERR_TICKET_INVALID", language);
    }

    const newSecretHash = await hashPassword(data.newPassword);

    const outcome = await withTransaction(
      ctx,
      async (tx): Promise<{ step: LoginStepResult; delivery: OtpDelivery | null }> => {
        const result = await repo.spChangePassword(
          tx,
          ticket.userId,
          sha256Hex(ticket.jti),
          ticket.expiresAt,
          newSecretHash,
        );
        if (!result.ok) {
          return { step: invalidStep("ERR_TICKET_INVALID", language), delivery: null };
        }

        if (result.twoFactorEnabled) {
          // Contacto del método (el resultado del SP solo trae el método).
          const info = await repo.fnGetTwoFactorChannelInfo(tx, ticket.userId);
          return prepareTwoFactorStep(
            tx,
            ticket,
            info ?? {
              method: normalizeTwoFactorMethod(result.twoFactorMethod ?? null),
              email: "",
              phone: null,
            },
            language,
            ctx,
          );
        }

        const tenants = await repo.fnGetAccessibleTenants(tx, ticket.userId, ticket.appId);
        return { step: await nextStepTicket(ticket, tenants, language), delivery: null };
      },
    );

    dispatchOtpDelivery(outcome.delivery);
    return outcome.step;
  },

  async createSession(
    data: InferType<typeof createSessionV1V>,
    ctx: AuditContext,
  ): Promise<SessionResult> {
    const ticket = await verifyTicket(data.ticket, "tenants");
    if (ticket === null) {
      return { ok: false };
    }

    const refreshToken = generateOpaqueToken();

    return withTransaction(ctx, async (tx) => {
      const payload = await repo.spCreateSession(tx, {
        userId: ticket.userId,
        appId: ticket.appId,
        customerId: data.customerId,
        ticketJtiHash: sha256Hex(ticket.jti),
        ticketExpiresAt: ticket.expiresAt,
        sessionTokenHash: sha256Hex(refreshToken),
        deviceIdentifier: ticket.deviceIdentifier,
        deviceName: ticket.deviceName,
        ipAddress: ctx.ipAddress,
        userAgent: ctx.userAgent,
      });
      if (!payload.ok) {
        // Ticket válido ⇒ la app del fallo se conoce (la del propio ticket).
        return { ok: false, appCode: ticket.appCode };
      }
      return buildSessionResult(payload, refreshToken, ticket.appCode);
    });
  },

  async refreshSession(
    refreshToken: string,
    // Solo seleccionó la cookie leída; por el invariante una-cookie-por-app,
    // la sesión del token pertenece a esta app.
    appCode: string,
    ctx: AuditContext,
  ): Promise<SessionResult> {
    const newRefreshToken = generateOpaqueToken();

    return withTransaction(ctx, async (tx) => {
      const payload = await repo.spRefreshSession(
        tx,
        sha256Hex(refreshToken),
        sha256Hex(newRefreshToken),
        ctx.ipAddress,
        ctx.userAgent,
      );
      if (!payload.ok) {
        return { ok: false, appCode };
      }
      return buildSessionResult(payload, newRefreshToken, appCode);
    });
  },

  async switchSession(
    data: InferType<typeof switchSessionV1V>,
    accessToken: string,
    refreshToken: string,
    ctx: AuditContext,
  ): Promise<SessionResult> {
    // El access token autentica la request; la cookie de refresh ancla
    // QUÉ sesión se revoca. Verificación real de firma contra la clave
    // del par cliente-app de los claims.
    const claims = peekAccessTokenClaims(accessToken);
    if (claims === null) {
      return { ok: false, appCode: data.appCode };
    }

    const newRefreshToken = generateOpaqueToken();

    return withTransaction(ctx, async (tx) => {
      const keyEncrypted = await repo.fnGetSigningKey(tx, claims.customerId, claims.appId);
      if (keyEncrypted === null) {
        return { ok: false, appCode: data.appCode };
      }
      const key = getSigningKey(claims.customerId, claims.appId, keyEncrypted);
      const verified = await verifyAccessToken(accessToken, key);
      if (verified === null) {
        return { ok: false, appCode: data.appCode };
      }

      const payload = await repo.spSwitchSession(
        tx,
        sha256Hex(refreshToken),
        data.customerId,
        sha256Hex(newRefreshToken),
        ctx.ipAddress,
        ctx.userAgent,
      );
      if (!payload.ok) {
        return { ok: false, appCode: data.appCode };
      }
      if (payload.userId !== verified.sub) {
        // Cookie y access token de usuarios distintos: jamás emitir
        throw new Error("switch: la sesión de la cookie no pertenece al usuario del token");
      }
      return buildSessionResult(payload, newRefreshToken, data.appCode);
    });
  },

  async revokeSession(refreshToken: string, ctx: AuditContext): Promise<void> {
    await withTransaction(ctx, (tx) => repo.spRevokeSession(tx, sha256Hex(refreshToken)));
  },

  /**
   * Introspección de un access token (endpoint de prueba): verifica firma +
   * exp + issuer contra la clave del par cliente-app de los claims — la misma
   * validación real que aplica `switch`. Devuelve los claims si es válido.
   * No consulta sesiones: comprueba SOLO la criptografía y vigencia del JWT.
   */
  async introspectAccessToken(
    accessToken: string,
    ctx: AuditContext,
  ): Promise<AccessTokenIntrospection> {
    const peeked = peekAccessTokenClaims(accessToken);
    if (peeked === null) {
      return { valid: false, claims: null };
    }

    return withTransaction(ctx, async (tx) => {
      const keyEncrypted = await repo.fnGetSigningKey(tx, peeked.customerId, peeked.appId);
      if (keyEncrypted === null) {
        return { valid: false, claims: null };
      }
      const key = getSigningKey(peeked.customerId, peeked.appId, keyEncrypted);
      const verified: VerifiedAccessToken | null = await verifyAccessToken(accessToken, key);
      if (verified === null) {
        return { valid: false, claims: null };
      }
      return {
        valid: true,
        claims: {
          sub: verified.sub,
          acu: verified.acu,
          customerId: verified.customerId,
          appId: verified.appId,
          sid: verified.sid,
          issuedAt: verified.issuedAt,
          expiresAt: verified.expiresAt,
        },
      };
    });
  },

  /**
   * Permisos efectivos FRESCOS de la sesión del access token (decisión #22:
   * auth_ws es la fuente de verdad operativa de permisos — la consumen el
   * front para la validación visual y los resource servers para autorizar
   * endpoints). Verificación real del token (misma que `switch`) + validez de
   * la sesión en BD: un token criptográficamente válido de una sesión ya
   * revocada NO obtiene permisos. `null` → 401 opaco.
   */
  async getSessionPermissions(
    accessToken: string,
    ctx: AuditContext,
  ): Promise<{ permissions: string[] } | null> {
    const peeked = peekAccessTokenClaims(accessToken);
    if (peeked === null) {
      return null;
    }

    return withTransaction(ctx, async (tx) => {
      const keyEncrypted = await repo.fnGetSigningKey(tx, peeked.customerId, peeked.appId);
      if (keyEncrypted === null) {
        return null;
      }
      const key = getSigningKey(peeked.customerId, peeked.appId, keyEncrypted);
      const verified: VerifiedAccessToken | null = await verifyAccessToken(accessToken, key);
      if (verified === null) {
        return null;
      }
      const permissions = await repo.fnGetSessionPermissions(tx, verified.sid);
      if (permissions === null) {
        return null;
      }
      return { permissions };
    });
  },

  async requestPasswordReset(
    data: InferType<typeof passwordResetRequestV1V>,
    ctx: AuditContext,
  ): Promise<{ issued: boolean }> {
    const rawToken = generateOpaqueToken();

    const result = await withTransaction(ctx, (tx) =>
      repo.spRequestPasswordReset(
        tx,
        data.identifier,
        sha256Hex(rawToken),
        PASSWORD_RESET_TTL_MINUTES,
        ctx.ipAddress,
        ctx.userAgent,
      ),
    );

    if (result.ok && result.email !== undefined) {
      // Fire-and-forget tras el commit: no bloquea la respuesta (siempre 202
      // opaca) ni añade latencia al camino "cuenta existe" (anti-oráculo §7).
      // El valor crudo del token solo viaja por el correo; nunca se persiste.
      void getMailer()
        .send(buildPasswordResetEmail(result.email, rawToken))
        .catch((err: unknown) => {
          console.error("Fallo al enviar correo de password reset:", err);
        });
    }
    return { issued: result.ok };
  },

  async confirmPasswordReset(
    data: InferType<typeof passwordResetConfirmV1V>,
    ctx: AuditContext,
  ): Promise<boolean> {
    const newSecretHash = await hashPassword(data.newPassword);
    const result = await withTransaction(ctx, (tx) =>
      repo.spConfirmPasswordReset(tx, sha256Hex(data.token), newSecretHash),
    );
    return result.ok;
  },

  /**
   * Aceptación de invitación (§4.2): fija la primera contraseña canjeando el
   * token de invitación (one-shot) y verifica el email de paso. Emite un ticket
   * de enrolamiento para continuar con el 2FA. Respuesta opaca en fallo.
   */
  async acceptInvitation(
    data: InferType<typeof invitationAcceptV1V>,
    ctx: AuditContext,
  ): Promise<InvitationAcceptResult> {
    const language = extractLanguage(ctx.acceptLanguage);
    const newSecretHash = await hashPassword(data.newPassword);

    const result = await withTransaction(ctx, (tx) =>
      repo.spConsumeInvitationToken(tx, sha256Hex(data.token), newSecretHash),
    );
    if (!result.ok || result.userId === undefined || result.email === undefined) {
      return invalidResult("ERR_INVITATION_INVALID", language);
    }

    const enrollmentTicket = await signEnrollmentTicket(result.userId, result.email);
    return { kind: "enroll-2fa", enrollmentTicket };
  },

  /**
   * Enrolamiento 2FA por método (2FA multicanal):
   *   totp  → genera y persiste (cifrado) un secreto nuevo; devuelve el
   *           material a mostrar UNA vez (secreto/URI/códigos).
   *   canal → fija el teléfono (si aplica), emite el challenge OTP y lo envía
   *           tras el commit; devuelve el destino enmascarado + recovery codes.
   * En ambos casos se regenera el lote de códigos de recuperación y NO se
   * activa el 2FA todavía (falta confirmar un código).
   */
  async enrollTwoFactor(
    data: InferType<typeof twoFactorEnrollV1V>,
    ctx: AuditContext,
  ): Promise<TwoFactorEnrollResult> {
    const language = extractLanguage(ctx.acceptLanguage);
    const ticket = await verifyEnrollmentTicket(data.enrollmentTicket);
    if (ticket === null) {
      return invalidResult("ERR_ENROLLMENT_INVALID", language);
    }

    const recoveryCodes = generateRecoveryCodes();
    const recoveryHashes = recoveryCodes.map((code) => sha256Hex(normalizeRecoveryCode(code)));

    const channelMethod = asChannelMethod(data.method);
    if (channelMethod === null) {
      // --- TOTP (flujo clásico, intacto) ---
      const secret = generateTotpSecretBase32();
      const secretEncrypted = encryptText(secret);

      const result = await withTransaction(ctx, (tx) =>
        repo.spEnrollTwoFactor(tx, ticket.userId, secretEncrypted, recoveryHashes),
      );
      if (!result.ok) {
        return invalidResult("ERR_ENROLLMENT_INVALID", language);
      }

      return {
        kind: "enrolled",
        method: "totp",
        secret,
        otpauthUri: buildOtpauthUri(secret, ticket.accountName, OTP_ISSUER),
        recoveryCodes,
      };
    }

    // --- Canal (sms/email/whatsapp) ---
    const code = generateOtpCode();
    const purpose = CHALLENGE_PURPOSE_BY_METHOD[channelMethod];

    const outcome = await withTransaction(
      ctx,
      async (tx): Promise<{ result: TwoFactorEnrollResult; delivery: OtpDelivery | null }> => {
        const enrolled = await repo.spEnrollTwoFactorChannel(tx, {
          userId: ticket.userId,
          method: channelMethod,
          phone: data.phone ?? null,
          recoveryCodeHashes: recoveryHashes,
          codeHash: hashOtpCode(ticket.userId, purpose, code),
          ttlSeconds: CHALLENGE_TTL_SECONDS,
          ipAddress: ctx.ipAddress,
          userAgent: ctx.userAgent,
        });
        if (!enrolled.ok) {
          return {
            result: invalidResult(
              enrolled.reason === "phone-required"
                ? "ERR_PHONE_REQUIRED"
                : "ERR_ENROLLMENT_INVALID",
              language,
            ),
            delivery: null,
          };
        }

        const email = enrolled.email ?? ticket.accountName;
        const phone = enrolled.phone ?? null;
        const destination =
          channelMethod === "email" ? maskEmail(email) : phone !== null ? maskPhone(phone) : "•••";
        return {
          result: {
            kind: "enrolled",
            method: channelMethod,
            destination,
            recoveryCodes,
            cooldownSeconds: RESEND_COOLDOWN_SECONDS,
          },
          delivery: { method: channelMethod, email, phone, code, locale: toLocale(language) },
        };
      },
    );

    dispatchOtpDelivery(outcome.delivery);
    return outcome.result;
  },

  /**
   * Reenvío del código OTP durante el enrolamiento de un método de canal.
   * Mismo throttle que el reenvío de login (3 reenvíos, cooldown 60 s),
   * keyed por usuario (el enrollmentTicket no expone su jti).
   */
  async enrollTwoFactorResend(
    data: InferType<typeof twoFactorEnrollResendV1V>,
    ctx: AuditContext,
  ): Promise<TwoFactorResendResult> {
    const language = extractLanguage(ctx.acceptLanguage);
    const ticket = await verifyEnrollmentTicket(data.enrollmentTicket);
    if (ticket === null) {
      return invalidResult("ERR_ENROLLMENT_INVALID", language);
    }

    const verdict = tryConsumeResend(sha256Hex(`enroll:${ticket.userId}`));
    if (!verdict.ok) {
      return invalidResult(
        verdict.reason === "cooldown" ? "ERR_2FA_RESEND_COOLDOWN" : "ERR_2FA_RESEND_LIMIT",
        language,
      );
    }

    const outcome = await withTransaction(
      ctx,
      async (tx): Promise<{ result: TwoFactorResendResult; delivery: OtpDelivery | null }> => {
        const pending = await repo.fnGetPendingTwoFactorEnrollment(tx, ticket.userId);
        if (pending === null) {
          return { result: invalidResult("ERR_ENROLLMENT_INVALID", language), delivery: null };
        }
        if (pending.method === "totp") {
          return {
            result: invalidResult("ERR_2FA_METHOD_NOT_RESENDABLE", language),
            delivery: null,
          };
        }

        const code = generateOtpCode();
        const purpose = CHALLENGE_PURPOSE_BY_METHOD[pending.method];
        const issued = await repo.spIssueTwoFactorChallenge(tx, {
          userId: ticket.userId,
          purpose,
          codeHash: hashOtpCode(ticket.userId, purpose, code),
          ttlSeconds: CHALLENGE_TTL_SECONDS,
          ipAddress: ctx.ipAddress,
          userAgent: ctx.userAgent,
        });
        if (!issued.ok) {
          return { result: invalidResult("ERR_ENROLLMENT_INVALID", language), delivery: null };
        }

        const email = issued.email ?? ticket.accountName;
        const phone = issued.phone ?? null;
        if (pending.method !== "email" && phone === null) {
          // Invariante rota: challenge sms/whatsapp pendiente sin teléfono.
          return {
            result: invalidResult("ERR_2FA_METHOD_NOT_RESENDABLE", language),
            delivery: null,
          };
        }

        const destination =
          pending.method === "email" ? maskEmail(email) : phone !== null ? maskPhone(phone) : "•••";
        return {
          result: {
            kind: "resent",
            destination,
            remaining: verdict.remaining,
            cooldownSeconds: RESEND_COOLDOWN_SECONDS,
          },
          delivery: { method: pending.method, email, phone, code, locale: toLocale(language) },
        };
      },
    );

    dispatchOtpDelivery(outcome.delivery);
    return outcome.result;
  },

  /**
   * Confirmación del enrolamiento según lo pendiente: verifica el primer
   * código (TOTP contra el secreto pendiente, o el OTP del challenge de
   * canal) y activa el 2FA. Para canales, el mismo canje sella la
   * verificación del contacto (phone/email_verified_at) en la BD.
   */
  async confirmTwoFactor(
    data: InferType<typeof twoFactorConfirmV1V>,
    ctx: AuditContext,
  ): Promise<TwoFactorConfirmResult> {
    const language = extractLanguage(ctx.acceptLanguage);
    const ticket = await verifyEnrollmentTicket(data.enrollmentTicket);
    if (ticket === null) {
      return invalidResult("ERR_ENROLLMENT_INVALID", language);
    }

    return withTransaction(ctx, async (tx) => {
      if (!/^\d{6}$/u.test(data.code)) {
        return invalidResult("ERR_2FA_INVALID_CODE", language);
      }

      const pending = await repo.fnGetPendingTwoFactorEnrollment(tx, ticket.userId);
      if (pending === null) {
        return invalidResult("ERR_2FA_INVALID_CODE", language);
      }

      if (pending.method === "totp") {
        const step = matchTotpStep(decryptText(pending.secretEncrypted), data.code);
        // Anti-replay: el step aceptado se registra también aquí — el primer
        // login con 2FA no podrá reutilizar el mismo código de la confirmación.
        if (step === null || !tryAcceptTotpStep(ticket.userId, step)) {
          return invalidResult("ERR_2FA_INVALID_CODE", language);
        }
        const activated = await repo.spActivateTwoFactor(tx, ticket.userId, "totp", null);
        if (!activated.ok) {
          return invalidResult("ERR_2FA_INVALID_CODE", language);
        }
        return { kind: "done" };
      }

      // Canal: el SP consume el challenge y activa en la misma transacción.
      const purpose = CHALLENGE_PURPOSE_BY_METHOD[pending.method];
      const activated = await repo.spActivateTwoFactor(
        tx,
        ticket.userId,
        pending.method,
        hashOtpCode(ticket.userId, purpose, data.code),
      );
      if (!activated.ok) {
        return invalidResult("ERR_2FA_INVALID_CODE", language);
      }
      return { kind: "done" };
    });
  },

  /**
   * JWKS (RFC 7517) con las claves PÚBLICAS de firma de cada par cliente-app.
   * Cualquier resource server lo cachea y valida los access tokens localmente
   * (selección por `kid`) sin poder emitir tokens: la privada nunca sale de
   * auth_ws. Un consumidor debe además exigir que el claim `app_id` del token
   * sea el suyo (el JWKS es de toda la plataforma).
   */
  async listPublicKeys(ctx: AuditContext): Promise<{ keys: JwkEd25519[] }> {
    const rows = await withTransaction(ctx, (tx) => repo.fnListSigningKeys(tx));
    const keys: JwkEd25519[] = [];
    for (const row of rows) {
      const key = getSigningKey(row.customerId, row.appId, row.signingKeyEncrypted);
      if (key.kid === undefined) {
        // Sin kid una clave no es seleccionable en un JWK Set: se omite
        // (configuración inválida del par cliente-app, no debería ocurrir).
        continue;
      }
      // Node deriva el JWK Ed25519 (kty=OKP, crv=Ed25519, x) desde el SPKI.
      const jwk = createPublicKey(key.publicKeyPem).export({ format: "jwk" }) as {
        kty?: string;
        crv?: string;
        x?: string;
      };
      if (jwk.kty !== "OKP" || typeof jwk.crv !== "string" || typeof jwk.x !== "string") {
        continue;
      }
      keys.push({
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        use: "sig",
        alg: "EdDSA",
        kid: key.kid,
        appCode: row.appCode,
      });
    }
    return { keys };
  },
};
