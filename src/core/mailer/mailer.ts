import { config } from "../../config";

// Capa de correo transaccional (CLAUDE.md §4 / Fase 2). Abstracción mínima con
// dos transportes: CONSOLA (default — registra el correo en el log, para
// desarrollo y fallback) y el smtp-service de notificacion_project
// (MAIL_TRANSPORT=smtp-service): auth_ws NO habla SMTP directo — encola el
// correo en ese microservicio (POST /v1/emails, auth por X-Api-Key) y él se
// encarga del despacho real (reintentos, cuentas SMTP, remitente). Su
// configuración se valida fail-fast al boot en config.ts.
//
// El valor CRUDO de los tokens viaja SOLO por este canal; jamás se persiste ni
// se loggea fuera del cuerpo del correo (la BD guarda solo su hash).

export interface EmailMessage {
  readonly to: string;
  readonly subject: string;
  readonly text: string;
  readonly html?: string;
}

export interface Mailer {
  send(message: EmailMessage): Promise<void>;
}

class ConsoleMailer implements Mailer {
  async send(message: EmailMessage): Promise<void> {
    console.info(
      `[mailer:console] to=${message.to} subject="${message.subject}"\n${message.text}`,
    );
  }
}

/**
 * Transporte real: delega el envío en el smtp-service (notificacion_project).
 * El correo se ENCOLA (`POST /v1/emails`, contrato snake_case) y el servicio
 * despacha con sus cuentas SMTP — el remitente lo resuelve él (por
 * `account_code` o la cuenta default del cliente de la api key). La
 * configuración viene validada del boot (config.ts exige SMTP_SERVICE_URL y
 * SMTP_SERVICE_API_KEY cuando MAIL_TRANSPORT=smtp-service); aquí solo se
 * re-verifica como cinturón de seguridad.
 */
class SmtpServiceMailer implements Mailer {
  private readonly baseUrl: string;
  private readonly apiKey: string;

  constructor() {
    const url = config.smtpServiceUrl;
    const apiKey = config.smtpServiceApiKey;
    if (url === null || url.length === 0 || apiKey === null || apiKey.length === 0) {
      // No debería alcanzarse: config.ts aborta el boot sin estas variables.
      throw new Error(
        "MAIL_TRANSPORT=smtp-service exige SMTP_SERVICE_URL y SMTP_SERVICE_API_KEY",
      );
    }
    this.baseUrl = url;
    this.apiKey = apiKey;
  }

  async send(message: EmailMessage): Promise<void> {
    const response = await fetch(`${this.baseUrl}/v1/emails`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": this.apiKey,
      },
      body: JSON.stringify({
        to: [message.to],
        subject: message.subject,
        body_text: message.text,
        ...(message.html !== undefined ? { body_html: message.html } : {}),
        ...(config.smtpServiceAccountCode !== null
          ? { account_code: config.smtpServiceAccountCode }
          : {}),
      }),
      signal: AbortSignal.timeout(10_000),
    });
    // Consumir el cuerpo libera el socket del agente HTTP (undici).
    await response.arrayBuffer().catch(() => undefined);
    // 201 = encolado; 200 = deduplicado (no aplica: no mandamos
    // idempotency_key). Cualquier otro estatus es fallo. Solo se propaga el
    // estatus: ni el cuerpo de la respuesta ni el del correo tocan el error.
    if (response.status !== 201 && response.status !== 200) {
      throw new Error(`smtp-service respondió ${response.status} al encolar el correo`);
    }
  }
}

/** Outbox en memoria para tests: los correos se capturan en vez de enviarse. */
export const memoryMailOutbox: EmailMessage[] = [];

class MemoryMailer implements Mailer {
  async send(message: EmailMessage): Promise<void> {
    memoryMailOutbox.push(message);
  }
}

/** Vacía y devuelve el outbox (solo tests). */
export function drainMailOutbox(): EmailMessage[] {
  return memoryMailOutbox.splice(0, memoryMailOutbox.length);
}

let cached: Mailer | null = null;

export function getMailer(): Mailer {
  if (cached === null) {
    cached =
      config.mailTransport === "smtp-service"
        ? new SmtpServiceMailer()
        : config.mailTransport === "memory"
          ? new MemoryMailer()
          : new ConsoleMailer();
  }
  return cached;
}

/** Correo con el código OTP 2FA (método de canal 'email'). */
export function buildTwoFactorCodeEmail(
  to: string,
  code: string,
  locale: "en" | "es",
): EmailMessage {
  if (locale === "es") {
    return {
      to,
      subject: "Tu código de acceso",
      text:
        `Tu código de acceso es: ${code}\n\n` +
        `Caduca en 10 minutos. Si no intentaste iniciar sesión, ignora este correo\n` +
        `y considera cambiar tu contraseña.`,
    };
  }
  return {
    to,
    subject: "Your access code",
    text:
      `Your access code is: ${code}\n\n` +
      `It expires in 10 minutes. If you did not try to sign in, ignore this email\n` +
      `and consider changing your password.`,
  };
}

/** Correo de recuperación de contraseña con el enlace a auth_app (/reset). */
export function buildPasswordResetEmail(to: string, rawToken: string): EmailMessage {
  const link = `${config.authAppBaseUrl}/reset?token=${encodeURIComponent(rawToken)}`;
  return {
    to,
    subject: "Restablece tu contraseña",
    text:
      `Recibimos una solicitud para restablecer tu contraseña.\n\n` +
      `Abre este enlace para elegir una nueva (caduca en 60 minutos):\n${link}\n\n` +
      `Si no fuiste tú, ignora este correo.`,
  };
}
