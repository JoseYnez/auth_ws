import type { InferType } from "structure-verifier";
import type { AuditContext } from "../../../core/audit/audit_context";
import { withTransaction } from "../../../core/db/with_transaction";
import { decryptText } from "../../../core/crypto/encryption";
import { hashPassword, verifyAgainstDummy, verifyPassword } from "../../../core/crypto/password";
import { generateOpaqueToken, sha256Hex } from "../../../core/crypto/token";
import { verifyTotpCode } from "../../../core/crypto/totp";
import {
  peekAccessTokenClaims,
  signAccessToken,
  verifyAccessToken,
} from "../../../core/jwt/access_token";
import { getSigningKey } from "../../../core/jwt/signing_keys";
import { signTicket, verifyTicket, type TicketPayload } from "../../../core/jwt/ticket";
import { authRepository as repo, type SessionPayloadOk, type Tenant } from "./auth_v1.repository";
import type {
  changePasswordV1V,
  createSessionV1V,
  loginV1V,
  passwordResetConfirmV1V,
  passwordResetRequestV1V,
  switchSessionV1V,
  twoFactorV1V,
} from "./auth_v1.verifier";

// Tipos del contrato §2.2 (espejo de AuthGateway en base_project)

export type LoginStepResult =
  | { kind: "invalid" }
  | { kind: "two-factor"; ticket: string; method: "totp" }
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
      session: SessionResponse;
      refreshToken: string;
      refreshTtlMinutes: number;
    }
  | { ok: false };

const PASSWORD_RESET_TTL_MINUTES = 60;

/**
 * Emite el access token del par cliente-app y arma la respuesta de sesión a
 * partir del payload de los SPs (crear / refresh / switch comparten esto).
 */
async function buildSessionResult(
  payload: SessionPayloadOk,
  refreshToken: string,
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
    },
    key,
    payload.accessTokenTtlMinutes,
  );
  return {
    ok: true,
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

/** Paso siguiente tras superar credenciales / 2FA / cambio de contraseña. */
async function nextStepTicket(
  base: Pick<TicketPayload, "userId" | "appId" | "appCode" | "deviceIdentifier" | "deviceName">,
  tenants: Tenant[],
): Promise<LoginStepResult> {
  if (tenants.length === 0) {
    // Usuario sin empresas en la app = respuesta opaca (CLAUDE.md §7)
    return { kind: "invalid" };
  }
  const { ticket } = await signTicket({ ...base, purpose: "tenants" });
  return { kind: "tenants", ticket, tenants };
}

export const authController = {
  async login(data: InferType<typeof loginV1V>, ctx: AuditContext): Promise<LoginStepResult> {
    return withTransaction(ctx, async (tx) => {
      const row = await repo.spLogin(tx, data.appCode, data.identifier);

      if (!row.ok) {
        // Igualar tiempos: el "usuario no existe" no debe distinguirse
        // de "contraseña incorrecta" por la latencia.
        await verifyAgainstDummy(data.password);
        return { kind: "invalid" };
      }

      const verified = await verifyPassword(row.secretHash, data.password);
      await repo.spRegisterLoginAttempt(tx, row.userId, row.appId, verified);
      if (!verified) {
        return { kind: "invalid" };
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
        return { kind: "change-password", ticket };
      }

      if (row.twoFactorEnabled) {
        const { ticket } = await signTicket({ ...ticketBase, purpose: "two-factor" });
        return { kind: "two-factor", ticket, method: "totp" };
      }

      return nextStepTicket(ticketBase, row.tenants);
    });
  },

  async twoFactor(
    data: InferType<typeof twoFactorV1V>,
    ctx: AuditContext,
  ): Promise<LoginStepResult> {
    const ticket = await verifyTicket(data.ticket, "two-factor");
    if (ticket === null) {
      return { kind: "invalid" };
    }

    return withTransaction(ctx, async (tx) => {
      let valid = false;

      if (/^\d{6}$/u.test(data.code)) {
        const secretEncrypted = await repo.fnGetTwoFactorSecret(tx, ticket.userId);
        if (secretEncrypted !== null) {
          valid = verifyTotpCode(decryptText(secretEncrypted), data.code);
        }
      }

      if (!valid) {
        // Código de recuperación (one-shot)
        const recovery = await repo.spConsumeRecoveryCode(tx, ticket.userId, sha256Hex(data.code));
        valid = recovery.ok;
      }

      if (!valid) {
        // Código incorrecto: el ticket NO se consume — se puede reintentar
        return { kind: "invalid" };
      }

      const consumed = await repo.spConsumeTicketJti(
        tx,
        ticket.userId,
        sha256Hex(ticket.jti),
        ticket.expiresAt,
      );
      if (!consumed.ok) {
        return { kind: "invalid" };
      }

      const tenants = await repo.fnGetAccessibleTenants(tx, ticket.userId, ticket.appId);
      return nextStepTicket(ticket, tenants);
    });
  },

  async changePassword(
    data: InferType<typeof changePasswordV1V>,
    ctx: AuditContext,
  ): Promise<LoginStepResult> {
    const ticket = await verifyTicket(data.ticket, "change-password");
    if (ticket === null) {
      return { kind: "invalid" };
    }

    const newSecretHash = await hashPassword(data.newPassword);

    return withTransaction(ctx, async (tx) => {
      const result = await repo.spChangePassword(
        tx,
        ticket.userId,
        sha256Hex(ticket.jti),
        ticket.expiresAt,
        newSecretHash,
      );
      if (!result.ok) {
        return { kind: "invalid" };
      }

      if (result.twoFactorEnabled) {
        const { ticket: nextTicket } = await signTicket({
          userId: ticket.userId,
          appId: ticket.appId,
          appCode: ticket.appCode,
          deviceIdentifier: ticket.deviceIdentifier,
          deviceName: ticket.deviceName,
          purpose: "two-factor",
        });
        return { kind: "two-factor", ticket: nextTicket, method: "totp" };
      }

      const tenants = await repo.fnGetAccessibleTenants(tx, ticket.userId, ticket.appId);
      return nextStepTicket(ticket, tenants);
    });
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
        return { ok: false };
      }
      return buildSessionResult(payload, refreshToken);
    });
  },

  async refreshSession(refreshToken: string, ctx: AuditContext): Promise<SessionResult> {
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
        return { ok: false };
      }
      return buildSessionResult(payload, newRefreshToken);
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
      return { ok: false };
    }

    const newRefreshToken = generateOpaqueToken();

    return withTransaction(ctx, async (tx) => {
      const keyEncrypted = await repo.fnGetSigningKey(tx, claims.customerId, claims.appId);
      if (keyEncrypted === null) {
        return { ok: false };
      }
      const key = getSigningKey(claims.customerId, claims.appId, keyEncrypted);
      const verified = await verifyAccessToken(accessToken, key);
      if (verified === null) {
        return { ok: false };
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
        return { ok: false };
      }
      if (payload.userId !== verified.sub) {
        // Cookie y access token de usuarios distintos: jamás emitir
        throw new Error("switch: la sesión de la cookie no pertenece al usuario del token");
      }
      return buildSessionResult(payload, newRefreshToken);
    });
  },

  async revokeSession(refreshToken: string, ctx: AuditContext): Promise<void> {
    await withTransaction(ctx, (tx) => repo.spRevokeSession(tx, sha256Hex(refreshToken)));
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

    // TODO(mailer): enviar rawToken por email (result.email) cuando exista
    // la integración de correo. El valor crudo NUNCA se loggea ni persiste.
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

  async listPublicKeys(ctx: AuditContext): Promise<{
    keys: Array<{ kid: string | null; alg: "EdDSA"; publicKeyPem: string; appCode: string }>;
  }> {
    const rows = await withTransaction(ctx, (tx) => repo.fnListSigningKeys(tx));
    const keys: Array<{
      kid: string | null;
      alg: "EdDSA";
      publicKeyPem: string;
      appCode: string;
    }> = [];
    for (const row of rows) {
      const key = getSigningKey(row.customerId, row.appId, row.signingKeyEncrypted);
      if (key.alg === "EdDSA") {
        keys.push({
          kid: key.kid ?? null,
          alg: "EdDSA",
          publicKeyPem: key.publicKeyPem,
          appCode: row.appCode,
        });
      }
    }
    return { keys };
  },
};
