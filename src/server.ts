import fastifyCookie from "@fastify/cookie";
import Fastify from "fastify";
import {
  serializerCompiler,
  validatorCompiler,
  type StructureVerifierTypeProvider,
} from "structure-verifier/fastify";
import { authV1Routes } from "./api/auth/v1/auth_v1.routes";
import { config } from "./config";
import { registerErrorHandler } from "./core/http/error_handler";

async function main(): Promise<void> {
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

  app.get("/health", async () => ({ status: "ok" }));

  await app.register(authV1Routes);

  await app.listen({ port: config.port, host: config.host });
}

main().catch((err) => {
  console.error("Fallo al arrancar auth_ws:", err);
  process.exit(1);
});
