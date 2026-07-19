import { randomInt } from "node:crypto";
import { sha256Hex } from "../crypto/token";

// Código OTP de los métodos 2FA de canal (sms/email/whatsapp): 6 dígitos
// CSPRNG generados SIEMPRE en auth_ws. A la BD viaja solo el hash; el crudo
// viaja únicamente por el canal (SMS/WhatsApp/correo) — jamás se loggea.

/** Propósitos de challenge 2FA en auth.user_verification_tokens. */
export type ChallengePurpose =
  | "two_factor_sms_challenge"
  | "two_factor_email_challenge"
  | "two_factor_whatsapp_challenge";

export type ChannelMethod = "sms" | "email" | "whatsapp";

export const CHALLENGE_PURPOSE_BY_METHOD: Record<ChannelMethod, ChallengePurpose> = {
  sms: "two_factor_sms_challenge",
  email: "two_factor_email_challenge",
  whatsapp: "two_factor_whatsapp_challenge",
};

/** TTL del challenge (contrato §6): el código caduca a los 10 minutos. */
export const CHALLENGE_TTL_SECONDS = 10 * 60;

/** Código de 6 dígitos con CSPRNG (randomInt es criptográficamente seguro). */
export function generateOtpCode(): string {
  return randomInt(0, 1_000_000).toString().padStart(6, "0");
}

/**
 * Hash del código que viaja a BD. La preimagen incluye usuario y purpose
 * porque `user_verification_tokens.token_hash` es UNIQUE GLOBAL: sin ellos,
 * dos usuarios con el mismo código de 6 dígitos colisionarían.
 */
export function hashOtpCode(userId: string, purpose: ChallengePurpose, code: string): string {
  return sha256Hex(`${userId}:${purpose}:${code}`);
}
