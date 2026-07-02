/**
 * Message resolution helper for auth responses.
 * Resolves message codes to developer and client messages based on language preference.
 */

export interface MessageResponse {
  code: string;
  messageForDeveloper: string;
  messageForClient: string;
  httpStatusCode: number;
  messageType: "error" | "success" | "info" | "warning";
}

const DEFAULT_LANGUAGE = "en";

/**
 * Catálogo de mensajes — única fuente de verdad (no hay tabla en BD).
 * Indexado por code y luego por idioma ISO 639-1. Vive en código a propósito:
 * son strings estáticos ligados a rutas de código, deben resolverse sin
 * round-trip y seguir funcionando aunque la BD esté caída (p. ej. el propio
 * ERR_INTERNAL_ERROR). Cada code DEBE definir la entrada DEFAULT_LANGUAGE
 * (se usa como fallback final).
 */
const MESSAGES: Record<string, Record<string, MessageResponse>> = {
  ERR_LOGIN_INVALID: {
    en: {
      code: "ERR_LOGIN_INVALID",
      messageForDeveloper:
        "Invalid credentials: user not found, password incorrect, or user blocked",
      messageForClient: "Invalid username or password",
      httpStatusCode: 401,
      messageType: "error",
    },
    es: {
      code: "ERR_LOGIN_INVALID",
      messageForDeveloper:
        "Credenciales inválidas: usuario no encontrado, contraseña incorrecta o usuario bloqueado",
      messageForClient: "Usuario o contraseña inválido",
      httpStatusCode: 401,
      messageType: "error",
    },
  },
  // ⚠️ PROHIBIDO conectar ERR_LOGIN_LOCKED, ERR_NO_TENANTS o ERR_TENANT_INACTIVE
  // al flujo de login/two-factor/change-password: filtrarían existencia o estado
  // de la cuenta (CLAUDE.md §7, decisión #19). Esas causas responden SIEMPRE con
  // ERR_LOGIN_INVALID. Existen en el catálogo para usos internos/futuros (p. ej.
  // consola de soporte autenticada).
  ERR_LOGIN_LOCKED: {
    en: {
      code: "ERR_LOGIN_LOCKED",
      messageForDeveloper: "User account locked due to too many failed login attempts",
      messageForClient: "Account temporarily locked. Try again later",
      httpStatusCode: 429,
      messageType: "error",
    },
    es: {
      code: "ERR_LOGIN_LOCKED",
      messageForDeveloper: "Cuenta de usuario bloqueada por demasiados intentos fallidos",
      messageForClient: "Cuenta bloqueada temporalmente. Intenta más tarde",
      httpStatusCode: 429,
      messageType: "error",
    },
  },
  ERR_2FA_INVALID_CODE: {
    en: {
      code: "ERR_2FA_INVALID_CODE",
      messageForDeveloper: "Invalid 2FA code or expired recovery code",
      messageForClient: "Invalid code. Please try again",
      httpStatusCode: 400,
      messageType: "error",
    },
    es: {
      code: "ERR_2FA_INVALID_CODE",
      messageForDeveloper: "Código 2FA inválido o código de recuperación expirado",
      messageForClient: "Código inválido. Intenta nuevamente",
      httpStatusCode: 400,
      messageType: "error",
    },
  },
  ERR_TICKET_INVALID: {
    en: {
      code: "ERR_TICKET_INVALID",
      messageForDeveloper: "Invalid or expired ticket. Session flow interrupted",
      messageForClient: "Your session has expired. Please login again",
      httpStatusCode: 401,
      messageType: "error",
    },
    es: {
      code: "ERR_TICKET_INVALID",
      messageForDeveloper: "Ticket inválido o expirado. Flujo de sesión interrumpido",
      messageForClient: "Tu sesión ha expirado. Por favor inicia sesión nuevamente",
      httpStatusCode: 401,
      messageType: "error",
    },
  },
  ERR_SESSION_INVALID: {
    en: {
      code: "ERR_SESSION_INVALID",
      messageForDeveloper: "Session is invalid, expired, or has been revoked",
      messageForClient: "Your session has expired. Please login again",
      httpStatusCode: 401,
      messageType: "error",
    },
    es: {
      code: "ERR_SESSION_INVALID",
      messageForDeveloper: "La sesión es inválida, ha expirado o ha sido revocada",
      messageForClient: "Tu sesión ha expirado. Por favor inicia sesión nuevamente",
      httpStatusCode: 401,
      messageType: "error",
    },
  },
  ERR_SESSION_EXPIRED: {
    en: {
      code: "ERR_SESSION_EXPIRED",
      messageForDeveloper: "Session has expired due to inactivity or time limit",
      messageForClient: "Your session has expired. Please login again",
      httpStatusCode: 401,
      messageType: "error",
    },
    es: {
      code: "ERR_SESSION_EXPIRED",
      messageForDeveloper: "La sesión ha expirado por inactividad o límite de tiempo",
      messageForClient: "Tu sesión ha expirado. Por favor inicia sesión nuevamente",
      httpStatusCode: 401,
      messageType: "error",
    },
  },
  ERR_NO_TENANTS: {
    en: {
      code: "ERR_NO_TENANTS",
      messageForDeveloper: "User has no access to any tenant for this app",
      messageForClient: "You do not have access to any organization",
      httpStatusCode: 403,
      messageType: "error",
    },
    es: {
      code: "ERR_NO_TENANTS",
      messageForDeveloper: "El usuario no tiene acceso a ningún cliente para esta app",
      messageForClient: "No tienes acceso a ninguna organización",
      httpStatusCode: 403,
      messageType: "error",
    },
  },
  ERR_TENANT_INACTIVE: {
    en: {
      code: "ERR_TENANT_INACTIVE",
      messageForDeveloper: "Tenant/customer is inactive or has been deleted",
      messageForClient: "The organization is not available",
      httpStatusCode: 403,
      messageType: "error",
    },
    es: {
      code: "ERR_TENANT_INACTIVE",
      messageForDeveloper: "El cliente/organización está inactivo o ha sido eliminado",
      messageForClient: "La organización no está disponible",
      httpStatusCode: 403,
      messageType: "error",
    },
  },
  SUCCESS_LOGIN: {
    en: {
      code: "SUCCESS_LOGIN",
      messageForDeveloper: "User successfully authenticated",
      messageForClient: "Login successful",
      httpStatusCode: 200,
      messageType: "success",
    },
    es: {
      code: "SUCCESS_LOGIN",
      messageForDeveloper: "Usuario autenticado exitosamente",
      messageForClient: "Inicio de sesión exitoso",
      httpStatusCode: 200,
      messageType: "success",
    },
  },
  SUCCESS_SESSION_CREATED: {
    en: {
      code: "SUCCESS_SESSION_CREATED",
      messageForDeveloper: "Session created successfully",
      messageForClient: "Session established",
      httpStatusCode: 200,
      messageType: "success",
    },
    es: {
      code: "SUCCESS_SESSION_CREATED",
      messageForDeveloper: "Sesión creada exitosamente",
      messageForClient: "Sesión establecida",
      httpStatusCode: 200,
      messageType: "success",
    },
  },
  SUCCESS_SESSION_REFRESHED: {
    en: {
      code: "SUCCESS_SESSION_REFRESHED",
      messageForDeveloper: "Session token refreshed successfully",
      messageForClient: "Session refreshed",
      httpStatusCode: 200,
      messageType: "success",
    },
    es: {
      code: "SUCCESS_SESSION_REFRESHED",
      messageForDeveloper: "Token de sesión actualizado exitosamente",
      messageForClient: "Sesión actualizada",
      httpStatusCode: 200,
      messageType: "success",
    },
  },
  ERR_INTERNAL_ERROR: {
    en: {
      code: "ERR_INTERNAL_ERROR",
      messageForDeveloper: "An internal server error occurred",
      messageForClient: "An unexpected error occurred. Please try again later",
      httpStatusCode: 500,
      messageType: "error",
    },
    es: {
      code: "ERR_INTERNAL_ERROR",
      messageForDeveloper: "Ocurrió un error interno del servidor",
      messageForClient: "Ocurrió un error inesperado. Por favor intenta más tarde",
      httpStatusCode: 500,
      messageType: "error",
    },
  },
};

/**
 * Extract language from Accept-Language header.
 * Format: "en-US,en;q=0.9,es;q=0.8"
 * Returns: "en" | "es" (ISO 639-1)
 */
export function extractLanguage(acceptLanguageHeader: string | undefined): string {
  if (!acceptLanguageHeader) {
    return "en";
  }

  const languages = acceptLanguageHeader
    .split(",")
    .map((lang) => (lang.split(";")[0] ?? "").trim().toLowerCase());

  // Return the first exact match from our supported set, or default to "en"
  for (const lang of languages) {
    if (lang === "es" || lang.startsWith("es-")) return "es";
    if (lang === "en" || lang.startsWith("en-")) return "en";
  }

  return "en";
}

/**
 * Get message response by code and language, with fallback to the default
 * language and then to a generic error.
 */
export function getMessageByCode(code: string, language: string = DEFAULT_LANGUAGE): MessageResponse {
  const byLanguage = MESSAGES[code];
  const resolved = byLanguage?.[language] ?? byLanguage?.[DEFAULT_LANGUAGE];
  return (
    resolved ?? {
      code,
      messageForDeveloper: `Unknown message code: ${code}`,
      messageForClient: "An unexpected error occurred",
      httpStatusCode: 500,
      messageType: "error",
    }
  );
}
