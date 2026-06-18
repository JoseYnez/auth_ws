import type { FastifyRequest } from "fastify";

/** audit.app_name: siempre el servicio ejecutor (decisión #12 del raíz). */
export const APP_NAME = "auth_ws";

/**
 * Contexto de auditoría de una request (CLAUDE.md §5). Se construye en la
 * route, una vez por request, y viaja hasta withTransaction, que lo vuelca
 * en los GUCs `audit.*` al abrir la transacción.
 */
export interface AuditContext {
  /** Identidad global (claim sub). NULL en login/2FA: lo setea el SP al resolverla. */
  readonly userId: string | null;
  /** Sesión vigente. NULL en login: sp_create_session lo setea al insertarla. */
  readonly sessionId: string | null;
  readonly appName: string;
  /** "<MÉTODO> <ruta>" del endpoint. */
  readonly action: string;
  readonly ipAddress: string | null;
  /** request.id de Fastify: correlaciona logs ↔ audit.event_log.stack_trace. */
  readonly requestId: string;
  /** No es GUC de auditoría: viaja a columnas user_agent de sesiones/tokens. */
  readonly userAgent: string | null;
}

export function buildAuditContext(
  req: FastifyRequest,
  actor?: { userId?: string; sessionId?: string },
): AuditContext {
  return {
    userId: actor?.userId ?? null,
    sessionId: actor?.sessionId ?? null,
    appName: APP_NAME,
    action: `${req.method} ${req.routeOptions.url ?? req.url}`,
    ipAddress: req.ip ?? null,
    requestId: String(req.id),
    userAgent: req.headers["user-agent"] ?? null,
  };
}
