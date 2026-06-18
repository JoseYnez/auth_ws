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

  await app.register(fastifyCookie);

  app.get("/health", async () => ({ status: "ok" }));

  await app.register(authV1Routes);

  await app.listen({ port: config.port, host: config.host });
}

main().catch((err) => {
  console.error("Fallo al arrancar auth_ws:", err);
  process.exit(1);
});
