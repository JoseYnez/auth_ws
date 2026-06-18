import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { StructureVerifierTypeProvider } from "structure-verifier/fastify";
import { config } from "../../../config";
import { buildAuditContext } from "../../../core/audit/audit_context";
import { authController } from "./auth_v1.controller";
import type { SessionResult } from "./auth_v1.controller";
import {
  changePasswordV1V,
  createSessionV1V,
  invalidResponseV1V,
  loginV1V,
  passwordResetConfirmV1V,
  passwordResetRequestV1V,
  sessionResponseV1V,
  switchSessionV1V,
  twoFactorV1V,
} from "./auth_v1.verifier";

// Cookie del refresh token (CLAUDE.md §6): httpOnly + Secure + SameSite=Strict,
// con Path acotado a los endpoints de sesión — el navegador no la manda a
// ningún otro sitio. El access token NUNCA va en cookie (memoria del SPA).
const REFRESH_COOKIE = "auth_refresh";
const REFRESH_COOKIE_PATH = "/auth/sessions";

function setRefreshCookie(reply: FastifyReply, token: string, ttlMinutes: number): void {
  reply.setCookie(REFRESH_COOKIE, token, {
    httpOnly: true,
    secure: config.cookieSecure,
    sameSite: "strict",
    path: REFRESH_COOKIE_PATH,
    maxAge: ttlMinutes * 60,
    ...(config.cookieDomain !== null ? { domain: config.cookieDomain } : {}),
  });
}

function clearRefreshCookie(reply: FastifyReply): void {
  reply.clearCookie(REFRESH_COOKIE, { path: REFRESH_COOKIE_PATH });
}

function readRefreshCookie(req: FastifyRequest): string | null {
  return req.cookies[REFRESH_COOKIE] ?? null;
}

function readBearerToken(req: FastifyRequest): string | null {
  const header = req.headers.authorization;
  if (header === undefined || !header.startsWith("Bearer ")) {
    return null;
  }
  return header.slice("Bearer ".length);
}

/** Mapea el resultado de sesión: 200 + cookie, o 401 opaco + cookie limpia. */
function sendSessionResult(reply: FastifyReply, result: SessionResult) {
  if (!result.ok) {
    clearRefreshCookie(reply);
    return reply.code(401).send({ error: "invalid" });
  }
  setRefreshCookie(reply, result.refreshToken, result.refreshTtlMinutes);
  return reply.code(200).send(result.session);
}

export async function authV1Routes(instance: FastifyInstance): Promise<void> {
  // El plugin recibe FastifyInstance "plano": recuperar el type provider para
  // que req.body se tipe por inferencia de los verifiers.
  const app = instance.withTypeProvider<StructureVerifierTypeProvider>();

  app.post("/auth/login", { schema: { body: loginV1V } }, async (req) => {
    return authController.login(req.body, buildAuditContext(req));
  });

  app.post("/auth/two-factor", { schema: { body: twoFactorV1V } }, async (req) => {
    return authController.twoFactor(req.body, buildAuditContext(req));
  });

  app.post("/auth/change-password", { schema: { body: changePasswordV1V } }, async (req) => {
    return authController.changePassword(req.body, buildAuditContext(req));
  });

  app.post(
    "/auth/sessions",
    {
      schema: {
        body: createSessionV1V,
        response: { 200: sessionResponseV1V, 401: invalidResponseV1V },
      },
    },
    async (req, reply) => {
      const result = await authController.createSession(req.body, buildAuditContext(req));
      return sendSessionResult(reply, result);
    },
  );

  app.post(
    "/auth/sessions/refresh",
    {
      schema: {
        response: { 200: sessionResponseV1V, 401: invalidResponseV1V },
      },
    },
    async (req, reply) => {
      const refreshToken = readRefreshCookie(req);
      if (refreshToken === null) {
        return reply.code(401).send({ error: "invalid" });
      }
      const result = await authController.refreshSession(refreshToken, buildAuditContext(req));
      return sendSessionResult(reply, result);
    },
  );

  app.post(
    "/auth/sessions/switch",
    {
      schema: {
        body: switchSessionV1V,
        response: { 200: sessionResponseV1V, 401: invalidResponseV1V },
      },
    },
    async (req, reply) => {
      const accessToken = readBearerToken(req);
      const refreshToken = readRefreshCookie(req);
      if (accessToken === null || refreshToken === null) {
        return reply.code(401).send({ error: "invalid" });
      }
      const result = await authController.switchSession(
        req.body,
        accessToken,
        refreshToken,
        buildAuditContext(req),
      );
      return sendSessionResult(reply, result);
    },
  );

  app.delete("/auth/sessions/current", async (req, reply) => {
    const refreshToken = readRefreshCookie(req);
    if (refreshToken !== null) {
      await authController.revokeSession(refreshToken, buildAuditContext(req));
    }
    clearRefreshCookie(reply);
    return reply.code(204).send();
  });

  app.post(
    "/auth/password-reset/request",
    { schema: { body: passwordResetRequestV1V } },
    async (req, reply) => {
      const result = await authController.requestPasswordReset(req.body, buildAuditContext(req));
      if (result.issued) {
        req.log.info("token de password reset emitido (envío de email pendiente de mailer)");
      }
      // 202 SIEMPRE: opaco, sin filtrar existencia de cuentas
      return reply.code(202).send({});
    },
  );

  app.post(
    "/auth/password-reset/confirm",
    { schema: { body: passwordResetConfirmV1V } },
    async (req, reply) => {
      const ok = await authController.confirmPasswordReset(req.body, buildAuditContext(req));
      if (!ok) {
        return reply.code(400).send({ error: "invalid-token" });
      }
      return reply.code(204).send();
    },
  );

  app.get("/auth/.well-known/keys", async (req, reply) => {
    const result = await authController.listPublicKeys(buildAuditContext(req));
    // Solo claves PÚBLICAS de pares asimétricos: cacheable sin riesgo
    return reply.header("cache-control", "public, max-age=3600").send(result);
  });
}
