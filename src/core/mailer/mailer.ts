import { config } from "../../config";

// Capa de correo transaccional (CLAUDE.md §4 / Fase 2). Abstracción mínima con
// un transporte de CONSOLA (registra el correo en el log) para desarrollo y como
// fallback. El transporte 'smtp' queda declarado pero pendiente de cablear un
// proveedor real; se falla ruidosamente para que nadie asuma que se envió.
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

let cached: Mailer | null = null;

export function getMailer(): Mailer {
  if (cached === null) {
    if (config.mailTransport === "smtp") {
      throw new Error(
        "MAIL_TRANSPORT=smtp aún no está implementado: configura un proveedor o usa 'console'",
      );
    }
    cached = new ConsoleMailer();
  }
  return cached;
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
