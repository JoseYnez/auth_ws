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
  // SameSite de la cookie de refresh. 'strict' (default, despliegue same-origin
  // — el modelo documentado en §6). Un SPA en OTRO origen exige 'none' (+ Secure)
  // para que el navegador mande la cookie en refresh/switch/logout cross-site;
  // 'none' abre superficie CSRF que la rotación + CORS mitigan parcialmente.
  COOKIE_SAMESITE: new V.StringNotNull({
    defaultValue: "strict",
    in: ["strict", "lax", "none"],
  }),
  // Lista blanca de orígenes permitidos para CORS, separados por coma.
  // Vacío = no se permite ningún origen cruzado (mismo origen sigue funcionando).
  CORS_ORIGINS: new V.StringNotNull({ defaultValue: "" }),
  // Base pública del auth_app (donde viven /reset y /invitation) para armar los
  // enlaces de los correos. Sin barra final.
  AUTH_APP_BASE_URL: new V.StringNotNull({ defaultValue: "http://localhost:4200" }),
  // Remitente de los correos transaccionales.
  MAIL_FROM: new V.StringNotNull({ defaultValue: "no-reply@localhost" }),
  // Transporte de correo: 'console' registra el correo en el log (dev/fallback,
  // default); 'smtp' envía de verdad vía nodemailer (exige SMTP_HOST — se
  // valida más abajo, fail-fast al boot).
  MAIL_TRANSPORT: new V.StringNotNull({ defaultValue: "console", in: ["console", "smtp"] }),
  // Servidor SMTP (solo con MAIL_TRANSPORT=smtp). SMTP_SECURE=true = TLS
  // implícito (puerto 465); false = claro/STARTTLS (587/25, nodemailer
  // negocia STARTTLS si el servidor lo ofrece).
  SMTP_HOST: new V.String({ maxLength: 255 }),
  SMTP_PORT: new V.NumberNotNull({ defaultValue: 587, min: 1, max: 65535 }),
  SMTP_SECURE: new V.BooleanNotNull({ defaultValue: false }),
  // Credenciales SMTP opcionales (relays internos sin auth): si se define una,
  // la otra es obligatoria (se valida más abajo).
  SMTP_USER: new V.String({ maxLength: 320 }),
  SMTP_PASS: new V.String({ maxLength: 512 }),
  // Apaga el rate limiting (solo para tests / desarrollo local). En producción
  // debe quedar activo: es la única defensa contra credential-stuffing y
  // fuerza bruta de TOTP a nivel de IP.
  RATE_LIMIT_DISABLED: new V.BooleanNotNull({ defaultValue: false }),
  LOG_LEVEL: new V.StringNotNull({
    defaultValue: "info",
    in: ["fatal", "error", "warn", "info", "debug", "trace"],
  }),
});

const result = envV.safeCheck(process.env);

if (!result.success) {
  console.error("Configuración de entorno inválida:", result.error.errorsObj);
  process.exit(1);
}

const env = result.value;

// Validación de secretos criptográficos AL BOOT (§9): un valor malformado debe
// impedir el arranque, no fallar en la primera petición. PLATFORM_MASTER_KEY es
// la clave AES-256-GCM (32 bytes) del cifrado en reposo; PLATFORM_TICKET_KEY se
// estira con sha256 para firmar los tickets, así que exigimos entropía mínima.
const masterKeyBytes = Buffer.from(env.PLATFORM_MASTER_KEY, "base64");
if (masterKeyBytes.length !== 32) {
  console.error(
    `PLATFORM_MASTER_KEY debe ser exactamente 32 bytes en base64 (son ${masterKeyBytes.length})`,
  );
  process.exit(1);
}
if (env.PLATFORM_TICKET_KEY.length < 32) {
  console.error("PLATFORM_TICKET_KEY debe tener al menos 32 caracteres de entropía");
  process.exit(1);
}

// Fail-fast del transporte SMTP (§9): con MAIL_TRANSPORT=smtp la configuración
// incompleta debe impedir el arranque, no descubrirse en el primer correo
// (los tokens de reset/invitación viajan SOLO por email).
if (env.MAIL_TRANSPORT === "smtp") {
  if (env.SMTP_HOST === null || env.SMTP_HOST.trim().length === 0) {
    console.error("MAIL_TRANSPORT=smtp exige SMTP_HOST");
    process.exit(1);
  }
  const hasUser = env.SMTP_USER !== null && env.SMTP_USER.length > 0;
  const hasPass = env.SMTP_PASS !== null && env.SMTP_PASS.length > 0;
  if (hasUser !== hasPass) {
    console.error("SMTP_USER y SMTP_PASS deben definirse juntos (o ninguno de los dos)");
    process.exit(1);
  }
}

export const config = {
  databaseUrl: env.DATABASE_URL,
  platformMasterKey: env.PLATFORM_MASTER_KEY,
  platformTicketKey: env.PLATFORM_TICKET_KEY,
  port: env.PORT,
  host: env.HOST,
  cookieDomain: env.COOKIE_DOMAIN,
  cookieSecure: env.COOKIE_SECURE,
  cookieSameSite: env.COOKIE_SAMESITE as "strict" | "lax" | "none",
  corsOrigins: env.CORS_ORIGINS.split(",")
    .map((o) => o.trim())
    .filter((o) => o.length > 0),
  authAppBaseUrl: env.AUTH_APP_BASE_URL.replace(/\/+$/u, ""),
  mailFrom: env.MAIL_FROM,
  mailTransport: env.MAIL_TRANSPORT as "console" | "smtp",
  smtpHost: env.SMTP_HOST,
  smtpPort: env.SMTP_PORT,
  smtpSecure: env.SMTP_SECURE,
  smtpUser: env.SMTP_USER,
  smtpPass: env.SMTP_PASS,
  rateLimitDisabled: env.RATE_LIMIT_DISABLED,
  logLevel: env.LOG_LEVEL,
} as const;
