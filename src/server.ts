import Fastify from "fastify";
import {
    serializerCompiler,
    validatorCompiler,
    type StructureVerifierTypeProvider,
} from "structure-verifier/fastify";
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

    app.get("/health", async () => ({ status: "ok" }));

    // Rutas de negocio (se registran por recurso versionado):
    // await app.register(authV1Routes);

    await app.listen({ port: config.port, host: config.host });
}

main().catch((err) => {
    // eslint-disable-next-line no-console
    console.error("Fallo al arrancar auth_ws:", err);
    process.exit(1);
});
