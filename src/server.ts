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
  const app = Fastify({
    trustProxy: true,
    logger: { level: config.logLevel },
  }).withTypeProvider<StructureVerifierTypeProvider>();

  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  registerErrorHandler(app);

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
