import type { FastifyReply, FastifyRequest } from "fastify";
import { config } from "../../config";

// Rate limiting por IP, en memoria y sin dependencias (misma filosofía que el
// CORS hand-rolled de server.ts). Es la primera línea contra credential
// stuffing y fuerza bruta de TOTP/reset a nivel de IP; el lockout por-cuenta
// (BD) y el cap de intentos de 2FA por ticket son defensas complementarias.
//
// LIMITACIÓN: el contador vive en el proceso. En un despliegue multi-instancia
// detrás de un balanceador, cada instancia cuenta por separado — para un límite
// global compartido hay que sustituir el Map por un store externo (Redis).
// `trustProxy: true` en server.ts hace que `req.ip` respete X-Forwarded-For.

interface Bucket {
  count: number;
  resetAt: number; // epoch ms en que se reinicia la ventana
}

interface RateLimitOptions {
  /** Máximo de peticiones permitidas por IP dentro de la ventana. */
  readonly max: number;
  /** Tamaño de la ventana en milisegundos. */
  readonly windowMs: number;
  /** Etiqueta para separar contadores por endpoint (login, 2fa, reset…). */
  readonly tag: string;
}

const buckets = new Map<string, Bucket>();
let lastSweep = Date.now();

// Barrido perezoso de buckets vencidos: evita crecimiento no acotado del Map
// sin necesitar un timer dedicado.
function sweep(now: number): void {
  if (now - lastSweep < 60_000) {
    return;
  }
  lastSweep = now;
  for (const [key, bucket] of buckets) {
    if (bucket.resetAt <= now) {
      buckets.delete(key);
    }
  }
}

function rateLimitedMessage(acceptLanguage: string | undefined) {
  const isSpanish = (acceptLanguage ?? "").toLowerCase().startsWith("es");
  return {
    code: "ERR_RATE_LIMITED",
    messageForClient: isSpanish
      ? "Demasiados intentos. Espera un momento e inténtalo de nuevo."
      : "Too many attempts. Please wait a moment and try again.",
    messageForDeveloper: "Rate limit exceeded for this IP.",
    httpStatusCode: 429,
  };
}

/**
 * `preHandler` de Fastify que aplica un límite de peticiones por IP. Cuando se
 * excede responde 429 con el mismo cuerpo opaco `{ kind: 'invalid', message }`
 * del contrato (§7/§19) para que el gateway del front lo procese como cualquier
 * otro error de auth. No revela estado de la cuenta.
 */
export function rateLimit(opts: RateLimitOptions) {
  return async function rateLimitPreHandler(
    req: FastifyRequest,
    reply: FastifyReply,
  ): Promise<FastifyReply | void> {
    if (config.rateLimitDisabled) {
      return;
    }

    const now = Date.now();
    sweep(now);

    const key = `${opts.tag}:${req.ip}`;
    let bucket = buckets.get(key);
    if (bucket === undefined || bucket.resetAt <= now) {
      bucket = { count: 0, resetAt: now + opts.windowMs };
      buckets.set(key, bucket);
    }
    bucket.count += 1;

    reply.header("X-RateLimit-Limit", String(opts.max));
    reply.header("X-RateLimit-Remaining", String(Math.max(opts.max - bucket.count, 0)));

    if (bucket.count > opts.max) {
      const retryAfterSeconds = Math.max(Math.ceil((bucket.resetAt - now) / 1000), 1);
      reply.header("Retry-After", String(retryAfterSeconds));
      return reply.code(429).send({
        kind: "invalid",
        message: rateLimitedMessage(req.headers["accept-language"]),
      });
    }
  };
}
