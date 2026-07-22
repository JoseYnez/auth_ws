import fastifyCookie from "@fastify/cookie";
import Fastify, { type FastifyInstance } from "fastify";
import {
  serializerCompiler,
  validatorCompiler,
  type StructureVerifierTypeProvider,
} from "structure-verifier/fastify";
import { authV1Routes } from "./api/auth/v1/auth_v1.routes";
import { config } from "./config";
import { pingDatabase } from "./core/db/ping";
import { registerErrorHandler } from "./core/http/error_handler";
import { getMailer } from "./core/mailer/mailer";

/**
 * Construye la instancia Fastify con todo registrado (compilers, hooks de
 * seguridad/CORS, cookie, rutas) SIN llamar a `listen()`. La usan tanto el
 * bootstrap (`main`) como los tests de integración (`app.inject()` en proceso,
 * sin abrir puerto). Es la única frontera de construcción de la app.
 */
export async function buildApp(): Promise<FastifyInstance> {
  // Instancia el mailer AL BOOT (no en el primer correo): con
  // MAIL_TRANSPORT=smtp-service una configuración inválida debe tumbar el
  // arranque (fail-fast §9) — los tokens de reset/invitación viajan solo por email.
  getMailer();
  // En desarrollo usamos pino-pretty para que la línea de acceso salga limpia
  // (sin el envoltorio JSON). En producción se mantiene JSON para agregadores.
  const isProd = process.env.NODE_ENV === "production";
  const app = Fastify({
    trustProxy: true,
    logger: {
      level: config.logLevel,
      ...(isProd
        ? {}
        : {
            transport: {
              target: "pino-pretty",
              options: {
                colorize: true,
                translateTime: false,
                ignore: "pid,hostname,reqId,level,time",
                messageFormat: "{msg}",
                hideObject: true,
              },
            },
          }),
    },
    // El log de acceso lo emitimos nosotros (hook onResponse) con un formato
    // legible; se desactiva el req/res en JSON de Fastify para no duplicar.
    disableRequestLogging: true,
  }).withTypeProvider<StructureVerifierTypeProvider>();

  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  registerErrorHandler(app);

  // Log de acceso legible: «fecha-hora método path status tiempo».
  // Ej.: 2026-06-25 14:03:21.187 POST /auth/login 200 12.4ms
  app.addHook("onResponse", async (request, reply) => {
    const now = new Date();
    const pad = (n: number, w = 2) => String(n).padStart(w, "0");
    const ts =
      `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ` +
      `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}.${pad(now.getMilliseconds(), 3)}`;
    const ms = reply.elapsedTime.toFixed(1);
    request.log.info(
      `${ts} ${request.method} ${request.url} ${reply.statusCode} ${ms}ms`,
    );
  });

  // CORS manual (sin plugin para evitar incompatibilidades de versión).
  // Solo se reflejan orígenes de la lista blanca: como el servicio emite la
  // cookie de refresh con credenciales, NUNCA debe permitirse un origen
  // arbitrario junto a Allow-Credentials: true.
  // Cabeceras de seguridad base en toda respuesta (API JSON: sin JS ni frames).
  app.addHook("onRequest", async (_request, reply) => {
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("X-Frame-Options", "DENY");
    reply.header("Referrer-Policy", "no-referrer");
    if (config.cookieSecure) {
      reply.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }
  });

  const allowedOrigins = new Set(config.corsOrigins);
  app.addHook("onRequest", async (request, reply) => {
    const origin = request.headers.origin;
    if (origin !== undefined && allowedOrigins.has(origin)) {
      reply.header("Access-Control-Allow-Origin", origin);
      reply.header("Vary", "Origin");
      reply.header("Access-Control-Allow-Methods", "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS");
      reply.header("Access-Control-Allow-Headers", "Content-Type,Authorization");
      reply.header("Access-Control-Allow-Credentials", "true");
      reply.header("Access-Control-Max-Age", "86400");
    }
  });

  app.options("*", (_request, reply) => {
    reply.code(204).send();
  });

  await app.register(fastifyCookie);

  // Liveness (¿el proceso responde?): siempre 200 mientras Fastify atienda.
  app.get("/health", async () => ({ status: "ok" }));

  // Readiness (¿el servicio puede operar?): verifica la dependencia crítica —
  // Postgres. 200 { status: 'ok', db: 'up' } si el pool responde; 503
  // { status: 'error', db: 'down' } si no. Sin cuerpos ni detalles que
  // filtren internals. Útil para orquestadores/balanceadores.
  app.get("/health/ready", async (_request, reply) => {
    try {
      await pingDatabase();
      return { status: "ok", db: "up" };
    } catch (err) {
      app.log.error({ err }, "health readiness: db unreachable");
      return reply.code(503).send({ status: "error", db: "down" });
    }
  });

  await app.register(authV1Routes);

  return app;
}

async function main(): Promise<void> {
  const app = await buildApp();
  await app.listen({ port: config.port, host: config.host });
}

// Solo arranca el servidor cuando se ejecuta como entrypoint (no al importar
// `buildApp` desde los tests). `require.main === module` distingue ambos casos.
if (require.main === module) {
  main().catch((err) => {
    console.error("Fallo al arrancar auth_ws:", err);
    process.exit(1);
  });
}
