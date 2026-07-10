import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { StructureVerifierTypeProvider } from "structure-verifier/fastify";
import { config } from "../../../config";
import { buildAuditContext } from "../../../core/audit/audit_context";
import { rateLimit } from "../../../core/http/rate_limit";
import { authController } from "./auth_v1.controller";
import type { LoginStepResult, SessionResult } from "./auth_v1.controller";
import {
  changePasswordV1V,
  createSessionV1V,
  invalidResponseV1V,
  invitationAcceptV1V,
  jwksResponseV1V,
  loginV1V,
  passwordResetConfirmV1V,
  passwordResetRequestV1V,
  sessionResponseV1V,
  switchSessionV1V,
  twoFactorConfirmV1V,
  twoFactorEnrollV1V,
  twoFactorV1V,
  verifyTokenResponseV1V,
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
    sameSite: config.cookieSameSite,
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

/**
 * Mapea un paso de login (login / two-factor / change-password) a HTTP. Los
 * pasos exitosos (`two-factor`/`change-password`/`tenants`) van con 200; el
 * `invalid` toma el `httpStatusCode` de su `message` (catálogo de mensajes:
 * 401 credencial/ticket inválido, 429 bloqueo, 400 código 2FA…). Si no trae
 * `message` se mantiene 200 (variante opaca sin estatus específico).
 */
function sendStep(reply: FastifyReply, result: LoginStepResult) {
  const status =
    result.kind === "invalid" && result.message !== undefined
      ? result.message.httpStatusCode
      : 200;
  return reply.code(status).send(result);
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

  app.post(
    "/auth/login",
    { schema: { body: loginV1V }, preHandler: rateLimit({ tag: "login", max: 10, windowMs: 60_000 }) },
    async (req, reply) => {
      const result = await authController.login(req.body, buildAuditContext(req));
      return sendStep(reply, result);
    },
  );

  app.post(
    "/auth/two-factor",
    { schema: { body: twoFactorV1V }, preHandler: rateLimit({ tag: "two-factor", max: 10, windowMs: 60_000 }) },
    async (req, reply) => {
      const result = await authController.twoFactor(req.body, buildAuditContext(req));
      return sendStep(reply, result);
    },
  );

  app.post(
    "/auth/change-password",
    {
      schema: { body: changePasswordV1V },
      preHandler: rateLimit({ tag: "change-password", max: 10, windowMs: 60_000 }),
    },
    async (req, reply) => {
      const result = await authController.changePassword(req.body, buildAuditContext(req));
      return sendStep(reply, result);
    },
  );

  // --- Onboarding: aceptación de invitación + enrolamiento de 2FA (§4.2) ---

  app.post(
    "/auth/invitation/accept",
    {
      schema: { body: invitationAcceptV1V },
      preHandler: rateLimit({ tag: "invitation-accept", max: 10, windowMs: 300_000 }),
    },
    async (req, reply) => {
      const result = await authController.acceptInvitation(req.body, buildAuditContext(req));
      if (result.kind === "invalid") {
        return reply.code(result.message.httpStatusCode).send(result);
      }
      return reply.code(200).send(result);
    },
  );

  app.post(
    "/auth/two-factor/enroll",
    {
      schema: { body: twoFactorEnrollV1V },
      preHandler: rateLimit({ tag: "2fa-enroll", max: 15, windowMs: 300_000 }),
    },
    async (req, reply) => {
      const result = await authController.enrollTwoFactor(req.body, buildAuditContext(req));
      if (result.kind === "invalid") {
        return reply.code(result.message.httpStatusCode).send(result);
      }
      // Solo los campos contratados (secreto/URI/códigos); no se filtra `kind`.
      return reply.code(200).send({
        secret: result.secret,
        otpauthUri: result.otpauthUri,
        recoveryCodes: result.recoveryCodes,
      });
    },
  );

  app.post(
    "/auth/two-factor/confirm",
    {
      schema: { body: twoFactorConfirmV1V },
      preHandler: rateLimit({ tag: "2fa-confirm", max: 10, windowMs: 60_000 }),
    },
    async (req, reply) => {
      const result = await authController.confirmTwoFactor(req.body, buildAuditContext(req));
      if (result.kind === "invalid") {
        return reply.code(result.message.httpStatusCode).send(result);
      }
      return reply.code(200).send(result);
    },
  );

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

  // Endpoint de prueba: valida un access token (Bearer) y devuelve sus claims.
  // Responde 200 SIEMPRE — `valid: false` cuando falta el token, la firma no
  // cuadra o está expirado; no es una frontera de seguridad, solo introspección.
  app.post(
    "/auth/sessions/verify",
    { schema: { response: { 200: verifyTokenResponseV1V } } },
    async (req, reply) => {
      const accessToken = readBearerToken(req);
      if (accessToken === null) {
        return reply.code(200).send({ valid: false, claims: null });
      }
      const result = await authController.introspectAccessToken(
        accessToken,
        buildAuditContext(req),
      );
      return reply.code(200).send(result);
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
    {
      schema: { body: passwordResetRequestV1V },
      preHandler: rateLimit({ tag: "pwreset-request", max: 5, windowMs: 300_000 }),
    },
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
    {
      schema: { body: passwordResetConfirmV1V },
      preHandler: rateLimit({ tag: "pwreset-confirm", max: 10, windowMs: 300_000 }),
    },
    async (req, reply) => {
      const ok = await authController.confirmPasswordReset(req.body, buildAuditContext(req));
      if (!ok) {
        return reply.code(400).send({ error: "invalid-token" });
      }
      return reply.code(204).send();
    },
  );

  app.get(
    "/auth/.well-known/keys",
    { schema: { response: { 200: jwksResponseV1V } } },
    async (req, reply) => {
      const result = await authController.listPublicKeys(buildAuditContext(req));
      // JWKS estándar (RFC 7517): solo material PÚBLICO, cacheable sin riesgo.
      return reply.header("cache-control", "public, max-age=3600").send(result);
    },
  );
}
