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
  // 'memory' captura los correos en un outbox (solo tests de integración).
  MAIL_TRANSPORT: new V.StringNotNull({
    defaultValue: "console",
    in: ["console", "smtp", "memory"],
  }),
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
  // Transporte del código OTP 2FA por SMS/WhatsApp: 'console' loggea el código
  // (dev/fallback, default); 'twilio' envía de verdad (exige TWILIO_* — se
  // valida más abajo, fail-fast al boot); 'memory' captura en un outbox (tests).
  // El canal email usa el mailer (MAIL_TRANSPORT).
  OTP_SENDER_TRANSPORT: new V.StringNotNull({
    defaultValue: "console",
    in: ["console", "twilio", "memory"],
  }),
  TWILIO_ACCOUNT_SID: new V.String({ maxLength: 64 }),
  TWILIO_AUTH_TOKEN: new V.String({ maxLength: 128 }),
  // Remitentes en E.164 (el prefijo whatsapp: lo añade el transporte).
  TWILIO_SMS_FROM: new V.String({ maxLength: 16 }),
  TWILIO_WHATSAPP_FROM: new V.String({ maxLength: 16 }),
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

// Fail-fast del transporte OTP (§9): con OTP_SENDER_TRANSPORT=twilio la
// configuración incompleta debe impedir el arranque, no descubrirse en el
// primer login con 2FA de canal (el código OTP viaja SOLO por ese canal).
if (env.OTP_SENDER_TRANSPORT === "twilio") {
  const missing: string[] = [];
  for (const [name, value] of [
    ["TWILIO_ACCOUNT_SID", env.TWILIO_ACCOUNT_SID],
    ["TWILIO_AUTH_TOKEN", env.TWILIO_AUTH_TOKEN],
    ["TWILIO_SMS_FROM", env.TWILIO_SMS_FROM],
    ["TWILIO_WHATSAPP_FROM", env.TWILIO_WHATSAPP_FROM],
  ] as const) {
    if (value === null || value.trim().length === 0) {
      missing.push(name);
    }
  }
  if (missing.length > 0) {
    console.error(`OTP_SENDER_TRANSPORT=twilio exige: ${missing.join(", ")}`);
    process.exit(1);
  }
}

// Validación fail-fast de PRODUCCIÓN (Fase 6.2): en `NODE_ENV=production` una
// configuración insegura debe ABORTAR el arranque, no descubrirse en caliente.
// En desarrollo estos valores son legítimos (HTTP local, sin CORS), así que solo
// se exigen cuando el despliegue se declara productivo. Mismo patrón (process.exit(1)
// con mensaje claro) que la validación de PLATFORM_MASTER_KEY de arriba.
if (process.env.NODE_ENV === "production") {
  const prodErrors: string[] = [];

  // La cookie de refresh viaja con credenciales: sin Secure el navegador la
  // expondría en texto claro. En producción SIEMPRE debe ir cifrada.
  if (!env.COOKIE_SECURE) {
    prodErrors.push(
      "COOKIE_SECURE no puede ser false en producción (la cookie de refresh exige HTTPS)",
    );
  }

  // CORS con credenciales + comodín = cualquier origen puede robar la sesión.
  // Vacío es igualmente inválido: el SPA no podría hablar con el servicio.
  const originList = env.CORS_ORIGINS.split(",")
    .map((o) => o.trim())
    .filter((o) => o.length > 0);
  if (originList.length === 0) {
    prodErrors.push(
      "CORS_ORIGINS no puede estar vacío en producción (declara la lista blanca de orígenes del front)",
    );
  }
  if (originList.includes("*")) {
    prodErrors.push(
      "CORS_ORIGINS no puede contener '*' en producción (comodín + cookie de credenciales = robo de sesión)",
    );
  }

  // Detecta llaves con valores de ejemplo obvios (los placeholders de .env.example
  // o cualquier variante de CHANGE_ME): un secreto de plantilla en producción es
  // tan grave como no tener secreto.
  const looksLikePlaceholder = (value: string): boolean =>
    /change_?me/iu.test(value) || value.includes("base64_32_bytes") || value.includes("example");
  for (const [name, value] of [
    ["PLATFORM_MASTER_KEY", env.PLATFORM_MASTER_KEY],
    ["PLATFORM_TICKET_KEY", env.PLATFORM_TICKET_KEY],
  ] as const) {
    if (looksLikePlaceholder(value)) {
      prodErrors.push(
        `${name} conserva un valor de ejemplo/placeholder; genera un secreto real (pnpm gen:secrets)`,
      );
    }
  }

  if (prodErrors.length > 0) {
    console.error("Configuración de PRODUCCIÓN inválida:");
    for (const msg of prodErrors) {
      console.error(`  - ${msg}`);
    }
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
  mailTransport: env.MAIL_TRANSPORT as "console" | "smtp" | "memory",
  smtpHost: env.SMTP_HOST,
  smtpPort: env.SMTP_PORT,
  smtpSecure: env.SMTP_SECURE,
  smtpUser: env.SMTP_USER,
  smtpPass: env.SMTP_PASS,
  otpSenderTransport: env.OTP_SENDER_TRANSPORT as "console" | "twilio" | "memory",
  twilioAccountSid: env.TWILIO_ACCOUNT_SID,
  twilioAuthToken: env.TWILIO_AUTH_TOKEN,
  twilioSmsFrom: env.TWILIO_SMS_FROM,
  twilioWhatsappFrom: env.TWILIO_WHATSAPP_FROM,
  rateLimitDisabled: env.RATE_LIMIT_DISABLED,
  logLevel: env.LOG_LEVEL,
} as const;
