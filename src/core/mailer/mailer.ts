import nodemailer, { type Transporter } from "nodemailer";
import type SMTPTransport from "nodemailer/lib/smtp-transport";
import { config } from "../../config";

// Capa de correo transaccional (CLAUDE.md §4 / Fase 2). Abstracción mínima con
// dos transportes: CONSOLA (default — registra el correo en el log, para
// desarrollo y fallback) y SMTP real vía nodemailer (MAIL_TRANSPORT=smtp; su
// configuración se valida fail-fast al boot en config.ts).
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
      `[mailer:console] from=${config.mailFrom} to=${message.to} subject="${message.subject}"\n${message.text}`,
    );
  }
}

/**
 * Transporte SMTP real (nodemailer). La configuración viene validada del boot
 * (config.ts exige SMTP_HOST y credenciales completas o ninguna cuando
 * MAIL_TRANSPORT=smtp); aquí solo se re-verifica como cinturón de seguridad.
 */
class SmtpMailer implements Mailer {
  private readonly transporter: Transporter;

  constructor() {
    const host = config.smtpHost;
    if (host === null || host.trim().length === 0) {
      // No debería alcanzarse: config.ts aborta el boot sin SMTP_HOST.
      throw new Error("MAIL_TRANSPORT=smtp exige SMTP_HOST");
    }
    const auth =
      config.smtpUser !== null &&
      config.smtpUser.length > 0 &&
      config.smtpPass !== null &&
      config.smtpPass.length > 0
        ? { user: config.smtpUser, pass: config.smtpPass }
        : undefined;
    const options: SMTPTransport.Options = {
      host,
      port: config.smtpPort,
      // true = TLS implícito (465); false = claro/STARTTLS negociado (587/25)
      secure: config.smtpSecure,
      ...(auth !== undefined ? { auth } : {}),
    };
    this.transporter = nodemailer.createTransport(options);
  }

  async send(message: EmailMessage): Promise<void> {
    await this.transporter.sendMail({
      from: config.mailFrom,
      to: message.to,
      subject: message.subject,
      text: message.text,
      ...(message.html !== undefined ? { html: message.html } : {}),
    });
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
      config.mailTransport === "smtp"
        ? new SmtpMailer()
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
