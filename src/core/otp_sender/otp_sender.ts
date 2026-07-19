import { URLSearchParams } from "node:url";
import { config } from "../../config";

// Envío del código OTP 2FA por SMS / WhatsApp (el canal email usa el mailer).
// Abstracción hermana del mailer (core/mailer): transporte CONSOLA (default
// dev — loggea el código), TWILIO (real; SMS y WhatsApp comparten la misma
// API de mensajes) y MEMORY (outbox en memoria para tests de integración).
//
// El código CRUDO viaja SOLO por este canal; jamás se persiste ni se loggea
// fuera del transporte console (que existe precisamente para desarrollo).

export type OtpChannel = "sms" | "whatsapp";

export interface OtpMessage {
  /** Destino en E.164 (el prefijo `whatsapp:` lo añade el transporte). */
  readonly to: string;
  readonly code: string;
  readonly channel: OtpChannel;
  readonly locale: "en" | "es";
}

export interface OtpSender {
  send(message: OtpMessage): Promise<void>;
}

/** Texto corto del mensaje (es/en) — común a todos los transportes. */
export function buildOtpText(code: string, locale: "en" | "es"): string {
  return locale === "es"
    ? `Tu código de acceso es ${code}. Caduca en 10 minutos. Si no lo solicitaste, ignora este mensaje.`
    : `Your access code is ${code}. It expires in 10 minutes. If you did not request it, ignore this message.`;
}

class ConsoleOtpSender implements OtpSender {
  async send(message: OtpMessage): Promise<void> {
    console.info(
      `[otp:console] channel=${message.channel} to=${message.to}\n${buildOtpText(message.code, message.locale)}`,
    );
  }
}

/**
 * Twilio Messages API sin SDK (filosofía de dependencias mínimas del mailer):
 * un único POST form-urlencoded con Basic Auth. WhatsApp usa la MISMA API con
 * el prefijo `whatsapp:` en To/From.
 */
class TwilioOtpSender implements OtpSender {
  async send(message: OtpMessage): Promise<void> {
    const sid = config.twilioAccountSid;
    const token = config.twilioAuthToken;
    if (sid === null || token === null) {
      // No debería alcanzarse: config.ts aborta el boot sin credenciales.
      throw new Error("OTP_SENDER_TRANSPORT=twilio exige TWILIO_ACCOUNT_SID y TWILIO_AUTH_TOKEN");
    }
    const isWhatsapp = message.channel === "whatsapp";
    const from = isWhatsapp ? config.twilioWhatsappFrom : config.twilioSmsFrom;
    if (from === null) {
      throw new Error(`Falta el remitente Twilio del canal ${message.channel}`);
    }
    const body = new URLSearchParams({
      To: isWhatsapp ? `whatsapp:${message.to}` : message.to,
      From: isWhatsapp ? `whatsapp:${from}` : from,
      Body: buildOtpText(message.code, message.locale),
    });
    const response = await globalThis.fetch(
      `https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(sid)}/Messages.json`,
      {
        method: "POST",
        headers: {
          authorization: `Basic ${Buffer.from(`${sid}:${token}`).toString("base64")}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      },
    );
    if (!response.ok) {
      // Sin cuerpo en el error: podría ecoar el mensaje (y el código) en logs.
      throw new Error(`Twilio respondió ${response.status} al enviar OTP por ${message.channel}`);
    }
  }
}

/** Outbox en memoria para tests: los códigos se capturan en vez de enviarse. */
export const memoryOtpOutbox: OtpMessage[] = [];

class MemoryOtpSender implements OtpSender {
  async send(message: OtpMessage): Promise<void> {
    memoryOtpOutbox.push(message);
  }
}

/** Vacía y devuelve el outbox (solo tests). */
export function drainOtpOutbox(): OtpMessage[] {
  return memoryOtpOutbox.splice(0, memoryOtpOutbox.length);
}

let cached: OtpSender | null = null;

export function getOtpSender(): OtpSender {
  if (cached === null) {
    cached =
      config.otpSenderTransport === "twilio"
        ? new TwilioOtpSender()
        : config.otpSenderTransport === "memory"
          ? new MemoryOtpSender()
          : new ConsoleOtpSender();
  }
  return cached;
}
