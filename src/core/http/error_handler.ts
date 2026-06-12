import type { FastifyInstance } from "fastify";
import { hasStructureVerifierValidationErrors } from "structure-verifier/fastify";

/**
 * Manejo global de errores (CLAUDE.md §7): validación → 400 con detalle por
 * campo; lo demás → 500 opaco con requestId (el detalle solo a logs). Los
 * errores de negocio NO llegan aquí: son respuestas tipadas del controller.
 */
export function registerErrorHandler(app: FastifyInstance): void {
    app.setErrorHandler((err, req, reply) => {
        if (hasStructureVerifierValidationErrors(err)) {
            return reply.status(400).send({ errors: err.validation });
        }
        req.log.error({ err }, "error no controlado");
        return reply.status(500).send({ error: "internal", requestId: String(req.id) });
    });
}
