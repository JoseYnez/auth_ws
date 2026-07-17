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
      // Detalle de qué campo falló (instancePath + message, SIN valores: el body
      // de auth no se loggea, §7). Facilita ubicar el 400 sin abrir DevTools.
      req.log.warn(
        { method: req.method, url: req.url, validation: err.validation },
        "400 validacion de body/params rechazada",
      );
      return reply.status(400).send({ errors: err.validation });
    }
    req.log.error({ err }, "error no controlado");
    return reply.status(500).send({ error: "internal", requestId: String(req.id) });
  });
}
