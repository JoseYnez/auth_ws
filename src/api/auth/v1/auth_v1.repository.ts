import type { TxClient } from "../../../core/db/with_transaction";

// Capa de acceso a BD: SOLO procedures/functions SECURITY DEFINER de
// db/06_auth_service_api.sql (role_auth_service no tiene tablas). Los
// procedures devuelven su resultado por el INOUT p_result (JSONB, camelCase);
// node-postgres lo entrega en rows[0].p_result ya parseado.

export interface Tenant {
  readonly id: string;
  readonly name: string;
}

export interface SpLoginOk {
  readonly ok: true;
  readonly userId: string;
  readonly appId: string;
  readonly secretHash: string;
  readonly mustChangeSecret: boolean;
  readonly twoFactorEnabled: boolean;
  readonly twoFactorMethod: string | null;
  readonly tenants: Tenant[];
  readonly maxFailedLoginAttempts: number;
  readonly lockoutMinutes: number;
}

export type SpLoginResult = SpLoginOk | { readonly ok: false; readonly reason: string };

export interface SessionPayloadOk {
  readonly ok: true;
  readonly sessionId: string;
  readonly acuId: string;
  readonly userId: string;
  readonly customerId: string;
  readonly appId: string;
  readonly sessionExpiresAt: string;
  readonly accessTokenTtlMinutes: number;
  readonly refreshTokenTtlMinutes: number;
  readonly signingKeyEncrypted: string | null;
  readonly user: { readonly id: string; readonly name: string; readonly email: string };
  readonly tenant: Tenant;
  readonly tenants: Tenant[];
  readonly permissions: string[];
}

export type SessionPayload = SessionPayloadOk | { readonly ok: false; readonly reason: string };

export interface SpChangePasswordResult {
  readonly ok: boolean;
  readonly reason?: string;
  readonly twoFactorEnabled?: boolean;
  readonly twoFactorMethod?: string | null;
}

async function callResult<T>(tx: TxClient, sql: string, params: unknown[]): Promise<T> {
  const result = await tx.query(sql, params);
  return result.rows[0]?.p_result as T;
}

export const authRepository = {
  spLogin(tx: TxClient, appCode: string, identifier: string): Promise<SpLoginResult> {
    return callResult(tx, "CALL auth.sp_login($1, $2, NULL)", [appCode, identifier]);
  },

  spRegisterLoginAttempt(
    tx: TxClient,
    userId: string,
    appId: string,
    success: boolean,
  ): Promise<{ ok: boolean; locked: boolean }> {
    return callResult(tx, "CALL auth.sp_register_login_attempt($1, $2, $3, NULL)", [
      userId,
      appId,
      success,
    ]);
  },

  spConsumeTicketJti(
    tx: TxClient,
    userId: string,
    jtiHash: string,
    expiresAt: Date,
  ): Promise<{ ok: boolean }> {
    return callResult(tx, "CALL auth.sp_consume_ticket_jti($1, $2, $3, NULL)", [
      userId,
      jtiHash,
      expiresAt,
    ]);
  },

  spCreateSession(
    tx: TxClient,
    args: {
      userId: string;
      appId: string;
      customerId: string;
      ticketJtiHash: string;
      ticketExpiresAt: Date;
      sessionTokenHash: string;
      deviceIdentifier: string;
      deviceName: string | null;
      ipAddress: string | null;
      userAgent: string | null;
    },
  ): Promise<SessionPayload> {
    return callResult(
      tx,
      "CALL auth.sp_create_session($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NULL)",
      [
        args.userId,
        args.appId,
        args.customerId,
        args.ticketJtiHash,
        args.ticketExpiresAt,
        args.sessionTokenHash,
        args.deviceIdentifier,
        args.deviceName,
        "{}",
        args.ipAddress,
        args.userAgent,
      ],
    );
  },

  spRefreshSession(
    tx: TxClient,
    sessionTokenHash: string,
    newSessionTokenHash: string,
    ipAddress: string | null,
    userAgent: string | null,
  ): Promise<SessionPayload> {
    return callResult(tx, "CALL auth.sp_refresh_session($1, $2, $3, $4, NULL)", [
      sessionTokenHash,
      newSessionTokenHash,
      ipAddress,
      userAgent,
    ]);
  },

  spSwitchSession(
    tx: TxClient,
    sessionTokenHash: string,
    newCustomerId: string,
    newSessionTokenHash: string,
    ipAddress: string | null,
    userAgent: string | null,
  ): Promise<SessionPayload> {
    return callResult(tx, "CALL auth.sp_switch_session($1, $2, $3, $4, $5, NULL)", [
      sessionTokenHash,
      newCustomerId,
      newSessionTokenHash,
      ipAddress,
      userAgent,
    ]);
  },

  spRevokeSession(
    tx: TxClient,
    sessionTokenHash: string,
  ): Promise<{ ok: boolean; revoked: boolean }> {
    return callResult(tx, "CALL auth.sp_revoke_session($1, NULL)", [sessionTokenHash]);
  },

  async fnGetTwoFactorSecret(tx: TxClient, userId: string): Promise<string | null> {
    const result = await tx.query("SELECT auth.fn_get_two_factor_secret($1) AS secret", [userId]);
    return (result.rows[0]?.secret as string | null) ?? null;
  },

  spConsumeRecoveryCode(tx: TxClient, userId: string, codeHash: string): Promise<{ ok: boolean }> {
    return callResult(tx, "CALL auth.sp_consume_recovery_code($1, $2, NULL)", [userId, codeHash]);
  },

  async fnGetAccessibleTenants(tx: TxClient, userId: string, appId: string): Promise<Tenant[]> {
    const result = await tx.query(
      "SELECT customer_id, customer_name FROM auth.fn_get_accessible_tenants($1, $2)",
      [userId, appId],
    );
    return result.rows.map((row) => ({
      id: row.customer_id as string,
      name: row.customer_name as string,
    }));
  },

  spRequestPasswordReset(
    tx: TxClient,
    identifier: string,
    tokenHash: string,
    ttlMinutes: number,
    ipAddress: string | null,
    userAgent: string | null,
  ): Promise<{ ok: boolean; userId?: string; email?: string; fullName?: string }> {
    return callResult(tx, "CALL auth.sp_request_password_reset($1, $2, $3, $4, $5, NULL)", [
      identifier,
      tokenHash,
      ttlMinutes,
      ipAddress,
      userAgent,
    ]);
  },

  spConfirmPasswordReset(
    tx: TxClient,
    tokenHash: string,
    newSecretHash: string,
  ): Promise<{ ok: boolean; reason?: string; userId?: string }> {
    return callResult(tx, "CALL auth.sp_confirm_password_reset($1, $2, NULL)", [
      tokenHash,
      newSecretHash,
    ]);
  },

  spChangePassword(
    tx: TxClient,
    userId: string,
    ticketJtiHash: string,
    ticketExpiresAt: Date,
    newSecretHash: string,
  ): Promise<SpChangePasswordResult> {
    return callResult(tx, "CALL auth.sp_change_password($1, $2, $3, $4, NULL)", [
      userId,
      ticketJtiHash,
      ticketExpiresAt,
      newSecretHash,
    ]);
  },

  async fnGetSigningKey(tx: TxClient, customerId: string, appId: string): Promise<string | null> {
    const result = await tx.query("SELECT auth.fn_get_signing_key($1, $2) AS key", [
      customerId,
      appId,
    ]);
    return (result.rows[0]?.key as string | null) ?? null;
  },

  async fnListSigningKeys(tx: TxClient): Promise<
    Array<{
      customerId: string;
      appId: string;
      appCode: string;
      signingKeyEncrypted: string;
    }>
  > {
    const result = await tx.query(
      "SELECT customer_id, app_id, app_code, signing_key_encrypted FROM auth.fn_list_signing_keys()",
    );
    return result.rows.map((row) => ({
      customerId: row.customer_id as string,
      appId: row.app_id as string,
      appCode: row.app_code as string,
      signingKeyEncrypted: row.signing_key_encrypted as string,
    }));
  },
};
