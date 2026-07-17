import type { FastifyInstance } from "fastify";
import { hasStructureVerifierValidationErrors } from "structure-verifier/fastify";

// Claves de body que NUNCA se loggean (§7): tokens/tickets/contraseñas/códigos.
// El resto (customerId, appCode, deviceIdentifier…) sí, para poder diagnosticar
// un 400 viendo el valor real que llegó. Enmascarar en vez de omitir deja ver
// que el campo venía presente.
const SENSITIVE_BODY_KEYS = new Set([
  "ticket",
  "password",
  "newPassword",
  "token",
  "code",
  "enrollmentTicket",
]);

function sanitizeBody(body: unknown): unknown {
  if (body === null || typeof body !== "object") {
    return body;
  }
  return Object.fromEntries(
    Object.entries(body as Record<string, unknown>).map(([k, v]) =>
      SENSITIVE_BODY_KEYS.has(k) ? [k, "«oculto»"] : [k, v],
    ),
  );
}

/**
 * Manejo global de errores (CLAUDE.md §7): validación → 400 con detalle por
 * campo; lo demás → 500 opaco con requestId (el detalle solo a logs). Los
 * errores de negocio NO llegan aquí: son respuestas tipadas del controller.
 */
export function registerErrorHandler(app: FastifyInstance): void {
  app.setErrorHandler((err, req, reply) => {
    if (hasStructureVerifierValidationErrors(err)) {
      // Qué campo falló (instancePath + message) y el body con los secretos
      // enmascarados (§7): así se ve el valor real que provocó el 400.
      req.log.warn(
        {
          method: req.method,
          url: req.url,
          validation: err.validation,
          body: sanitizeBody(req.body),
        },
        "400 validacion de body/params rechazada",
      );
      return reply.status(400).send({ errors: err.validation });
    }
    req.log.error({ err }, "error no controlado");
    return reply.status(500).send({ error: "internal", requestId: String(req.id) });
  });
}
