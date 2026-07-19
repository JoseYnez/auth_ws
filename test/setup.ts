/**
 * setup.ts — Configura el entorno de los tests de integración ANTES de que se
 * importe `config`/`buildApp` (los setupFiles de vitest corren antes de evaluar
 * el módulo de test). Fija los defaults contra el Postgres de PRUEBA ya sembrado.
 *
 * Los valores usan `??=`: si el entorno (CI) ya trae la variable, gana la del
 * entorno; si no, se usa el default local. Los secretos de aquí son de PRUEBA
 * (coinciden con los del contenedor sembrado), NUNCA de producción.
 *
 * Nota: `config.ts` hace `import "dotenv/config"`, pero dotenv NO sobrescribe
 * variables ya presentes en process.env — por eso fijarlas aquí gana sobre `.env`.
 */

process.env.NODE_ENV ??= "test";
// Postgres de prueba (role_auth_service, puerto 5433).
process.env.DATABASE_URL ??= "postgresql://role_auth_service:authpw@localhost:5433/core_db";
// Llaves de PRUEBA con las que se cifró el material sembrado en esa BD.
process.env.PLATFORM_MASTER_KEY ??= "0UulwicDCuALaBBy1AhEIpItzTVbD8lwhvswf7AwuVo=";
process.env.PLATFORM_TICKET_KEY ??= "Xk4SOFhEi2fvpzQkt1JwVm8h3IhtcQM3bdphv35iXoQ=";
// Sin HTTPS en los tests: la cookie de refresh no puede exigir Secure.
process.env.COOKIE_SECURE ??= "false";
// El rate limiting mataría las corridas repetidas; se apaga en tests.
process.env.RATE_LIMIT_DISABLED ??= "true";
// Transportes en memoria: los códigos OTP y correos se CAPTURAN en un outbox
// (drainOtpOutbox / drainMailOutbox) en vez de enviarse — así los tests de
// 2FA multicanal leen el código como lo haría el usuario.
process.env.OTP_SENDER_TRANSPORT ??= "memory";
process.env.MAIL_TRANSPORT ??= "memory";
process.env.CORS_ORIGINS ??= "http://localhost:4200";
// Menos ruido en la salida de los tests (config valida el enum de LOG_LEVEL).
process.env.LOG_LEVEL ??= "error";
