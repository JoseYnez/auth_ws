import "dotenv/config";
import { Verifiers as V } from "structure-verifier";

// Validación del entorno al boot (CLAUDE.md §9): si falta algo, el proceso
// no arranca. Las propiedades no declaradas de process.env se descartan.
const envV = new V.ObjectNotNull({
    DATABASE_URL: new V.StringNotNull({ minLength: 1 }),
    PLATFORM_MASTER_KEY: new V.StringNotNull({ minLength: 1 }),
    PLATFORM_TICKET_KEY: new V.StringNotNull({ minLength: 1 }),
    PORT: new V.NumberNotNull({ defaultValue: 3001, min: 1, max: 65535 }),
    HOST: new V.StringNotNull({ defaultValue: "0.0.0.0" }),
    COOKIE_DOMAIN: new V.String(),
    // false SOLO en desarrollo local sin HTTPS
    COOKIE_SECURE: new V.BooleanNotNull({ defaultValue: true }),
    LOG_LEVEL: new V.StringNotNull({
        defaultValue: "info",
        in: ["fatal", "error", "warn", "info", "debug", "trace"],
    }),
});

const result = envV.safeCheck(process.env);

if (!result.success) {
    // eslint-disable-next-line no-console
    console.error("Configuración de entorno inválida:", result.error.errorsObj);
    process.exit(1);
}

const env = result.value;

export const config = {
    databaseUrl: env.DATABASE_URL,
    platformMasterKey: env.PLATFORM_MASTER_KEY,
    platformTicketKey: env.PLATFORM_TICKET_KEY,
    port: env.PORT,
    host: env.HOST,
    cookieDomain: env.COOKIE_DOMAIN,
    cookieSecure: env.COOKIE_SECURE,
    logLevel: env.LOG_LEVEL,
} as const;
