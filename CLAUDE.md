# CLAUDE.md — auth_ws (API de autenticación y permisos)

> Versión 1.0 — 2026-06-11
>
> Estándar de implementación del servicio de autenticación. Subordinado a
> [../CLAUDE.md](../CLAUDE.md) (lógica de negocio) y a
> [../db/CLAUDE.md](../db/CLAUDE.md) (objetos de BD). Si algo aquí contradice
> esos documentos, prevalecen ellos.

---

## 0. Propósito y stack

`auth_ws` implementa el contrato de §2.2 del CLAUDE.md raíz: login por pasos,
2FA TOTP, sesiones, refresh, switch, logout y password reset. Es el **único
emisor, rotador y revocador de tokens** de la plataforma: ningún otro
servicio firma ni emite tokens.

| Pieza | Elección |
|---|---|
| Runtime | Node.js LTS, TypeScript estricto (`strict: true`) |
| HTTP | Fastify ≥ 4, `trustProxy: true` |
| Validación | `structure-verifier` ≥ 1.1.x con su adaptador `structure-verifier/fastify`. Hoy instalada como `file:../../libs/structure-verifier` (la 1.1.x no está publicada en npm); al publicarla, cambiar a la versión de registro |
| BD | `pg` (node-postgres), un solo pool, usuario **`role_auth_service`** |
| Hash de contraseñas | **argon2id** (paquete `argon2`) |
| JWT | `jose` (firma **EdDSA/Ed25519**; JWKS público en formato JWK) |
| Cifrado en reposo | AES-256-GCM con `PLATFORM_MASTER_KEY` (env) |

Servicio **stateless**: todo estado vive en la BD (o en el propio token). No
hay Redis ni memoria compartida; cualquier instancia puede atender cualquier
request.

---

## 1. Estructura de carpetas

```
auth_ws/
├── src/
│   ├── api/
│   │   └── auth/
│   │       └── v1/
│   │           ├── auth_v1.routes.ts        ← rutas Fastify (método, URL, schema, hooks)
│   │           ├── auth_v1.verifier.ts      ← verifiers de body/params/query/response
│   │           ├── auth_v1.controller.ts    ← casos de uso (sin SQL, sin tipos de Fastify)
│   │           └── auth_v1.repository.ts    ← llamadas a procedures (recibe tx, nunca pool)
│   ├── core/
│   │   ├── db/
│   │   │   ├── pool.ts                      ← pool pg (privado del módulo)
│   │   │   └── with_transaction.ts          ← ÚNICA puerta a la BD (§4)
│   │   ├── audit/
│   │   │   └── audit_context.ts             ← tipo AuditContext + plugin onRequest
│   │   ├── crypto/
│   │   │   ├── password.ts                  ← argon2id hash/verify
│   │   │   ├── token.ts                     ← CSPRNG + sha256
│   │   │   └── encryption.ts                ← AES-256-GCM (campos *_encrypted)
│   │   ├── jwt/
│   │   │   ├── access_token.ts              ← firma/verificación access token
│   │   │   └── ticket.ts                    ← ticket efímero de login
│   │   └── http/
│   │       ├── error_handler.ts             ← setErrorHandler global
│   │       └── plugins.ts                   ← registro de compilers y hooks
│   ├── config.ts                            ← lectura y validación de env (falla al boot si falta algo)
│   └── server.ts                            ← bootstrap
├── package.json                             ← independiente (sin workspace)
└── CLAUDE.md                                ← este documento
```

Un recurso = una carpeta versionada `src/api/<recurso>/v1/`. Las versiones
nuevas (`v2/`) conviven con las anteriores; nunca se rompe un contrato
publicado.

---

## 2. Estándar de endpoint

Anatomía obligatoria de cada endpoint, en cuatro capas con responsabilidades
cerradas:

| Capa | Archivo | Hace | NO hace |
|---|---|---|---|
| Route | `*_v1.routes.ts` | Declara método+URL, engancha verifiers en `schema`, construye `AuditContext`, llama al controller, mapea resultado→HTTP | Lógica de negocio, SQL |
| Verifier | `*_v1.verifier.ts` | Define los esquemas de entrada Y salida con `structure-verifier` | Validación de negocio contra BD |
| Controller | `*_v1.controller.ts` | Caso de uso: orquesta repository + crypto + jwt dentro de `withTransaction` | Tocar `request`/`reply`, SQL crudo |
| Repository | `*_v1.repository.ts` | `CALL`/`SELECT` a procedures `SECURITY DEFINER`; recibe `tx` | Abrir transacciones, decidir negocio |

Esqueleto canónico:

```ts
// auth_v1.verifier.ts
import { Verifiers as V } from "structure-verifier";

// API ≥ 1.1.x: properties como primer argumento, condiciones como segundo.
export const loginV1V = new V.ObjectNotNull({
    appCode: new V.StringNotNull({ minLength: 1, maxLength: 64 }),
    identifier: new V.StringNotNull({ minLength: 1, maxLength: 320 }),
    password: new V.StringNotNull({ minLength: 1, maxLength: 256 }),
    deviceIdentifier: new V.StringNotNull({ minLength: 1, maxLength: 128 }),
    deviceName: new V.String({ maxLength: 128 }),
}, { strictMode: true });

// auth_v1.routes.ts
app.post("/auth/login", { schema: { body: loginV1V } }, async (req, reply) => {
    const ctx = buildAuditContext(req);          // §5
    const result = await authController.login(req.body, ctx);
    return sendStep(reply, result);              // HTTP = message.httpStatusCode (§7)
});

// auth_v1.controller.ts
async login(data: InferType<typeof loginV1V>, ctx: AuditContext): Promise<LoginResult> {
    return withTransaction(ctx, async (tx) => {
        const row = await authRepository.spLogin(tx, data, ctx);
        // verificación argon2id, decisión two-factor/change-password/tenants…
    });
}
```

Reglas del estándar:

1. **Todo body/params/query pasa por un verifier** con `strictMode: true` en
   el objeto raíz (propiedades no declaradas = rechazo). Sin verifier no hay
   ruta.
2. **Las respuestas también se declaran** (`schema.response`) — el
   `serializerCompiler` de structure-verifier garantiza que jamás se filtre
   un campo no contratado (hashes, claves, ids internos).
3. Los controllers reciben `InferType<typeof verifier>` — **prohibido
   re-tipar a mano** lo que el verifier ya infiere.
4. URLs en **kebab-case**, JSON en **camelCase**, BD en **snake_case**; el
   mapeo camel↔snake ocurre solo en el repository.
5. Un endpoint = **una transacción** (`withTransaction`). Nunca dos
   transacciones por request, nunca SQL fuera de ella.
6. Nada de lógica en hooks globales salvo contexto/seguridad; la lógica vive
   en controllers testeables sin Fastify.

---

## 3. Acceso a BD: cero tablas, solo procedures

`role_auth_service` no tiene **ningún** privilegio de tabla. El repository
solo ejecuta `CALL auth.sp_*` / `SELECT auth.fn_*`. Si un caso de uso
necesita un dato nuevo, **se crea o amplía un procedure en `db/`** (con su
`GRANT EXECUTE` declarado junto al procedure, mismo script) — jamás se pide
un GRANT de tabla.

Objetos que consume este servicio (definidos en
`db/06_auth_service_api.sql`):

| Objeto | Uso |
|---|---|
| `auth.sp_login` | Resuelve identidad (username o email), valida lockout, devuelve `secret_hash` + flags 2FA/`must_change_secret` + empresas accesibles |
| `auth.sp_register_login_attempt` | Registra éxito/fallo del verify argon2id; contadores y `locked_until_at` (umbrales de `core.apps` — en credenciales aún no hay cliente) |
| `auth.sp_consume_ticket_jti` | One-shot del ticket: registra `sha256(jti)` en `user_verification_tokens` (purpose `login_ticket`); el UNIQUE rechaza el segundo canje |
| `auth.sp_create_session` | Consume jti + valida tripleta (4 niveles) + `max_sessions` (revoca las más antiguas) + inserta sesión; devuelve payload completo |
| `auth.sp_refresh_session` | Rotación encadenada; **reuso de hash rotado = revoca el descendiente vivo** y revalida los 4 niveles |
| `auth.sp_switch_session` | Revoca la sesión actual (anclada por cookie) y abre una nueva contra la otra tripleta |
| `auth.sp_revoke_session` | Logout: `status='inactive'` + `revoked_at`. Idempotente |
| `auth.sp_change_password` | Cambio con ticket `change-password` (must_change): consume jti, fija hash, revoca sesiones vivas |
| `auth.sp_request_password_reset` / `sp_confirm_password_reset` | Token `password_reset` (solo sha256 a BD); confirm revoca todas las sesiones |
| `auth.sp_consume_recovery_code` | Canje one-shot de código de recuperación 2FA |
| `auth.fn_get_two_factor_secret` | Secreto TOTP cifrado (descifrado y verificación RFC 6238 en el servicio) |
| `auth.fn_get_accessible_tenants` | Empresas accesibles (intersección 4 niveles) — pasos 2FA/change-password |
| `auth.fn_get_signing_key` / `fn_list_signing_keys` | Claves de firma cifradas (verificar access en switch / `/.well-known/keys`) |

(`auth.sp_open_session` y `auth.fn_build_session_payload` son internos del
script: sin GRANT, solo invocables desde los procedures públicos.)

Convención de contexto: el servicio setea los 6 GUCs en `withTransaction`;
los SPs **añaden lo que el servicio no conoce aún** con
`PERFORM set_config(..., true)` — `audit.user_id` al resolver la identidad
(huevo-y-gallina del login) y `audit.user_session` al crear/rotar la sesión.
Los resultados van por `INOUT p_result JSONB` (claves camelCase).

La verificación argon2id ocurre **en Node** (la BD no tiene argon2): el SP
entrega el `secret_hash` solo tras validar app + identidad + vigencia, y ese
hash no sale nunca del controller (ni a logs ni a respuestas).

---

## 4. `withTransaction`: la única puerta a la BD

```ts
export async function withTransaction<T>(
    ctx: AuditContext,
    fn: (tx: TxClient) => Promise<T>,
): Promise<T> {
    const client = await pool.connect();
    try {
        await client.query("BEGIN");
        await client.query(
            `SELECT set_config('audit.user_id',            $1, true),
                    set_config('audit.user_session',       $2, true),
                    set_config('audit.app_name',           $3, true),
                    set_config('audit.action',             $4, true),
                    set_config('audit.ip_address',         $5, true),
                    set_config('audit.stack_trace',        $6, true)`,
            [ctx.userId ?? "", ctx.sessionId ?? "", ctx.appName,
             ctx.action, ctx.ipAddress ?? "", ctx.requestId],
        );
        const result = await fn(client);
        await client.query("COMMIT");
        return result;
    } catch (err) {
        await client.query("ROLLBACK");
        throw err;
    } finally {
        client.release();
    }
}
```

- El pool **no se exporta**: repositories y controllers solo conocen `tx`.
  Así es estructuralmente imposible ejecutar SQL sin contexto de auditoría.
- `set_config(..., true)` = scope de transacción: el contexto muere con el
  COMMIT/ROLLBACK; no contamina la siguiente request del mismo cliente del
  pool.

---

## 5. Contexto de auditoría (`AuditContext`)

Se construye **en la route**, una vez por request:

| Campo | GUC | Origen en `auth_ws` |
|---|---|---|
| `userId` | `audit.user_id` | Claim `sub` del access/refresh validado. En login/2FA/canje de ticket es `NULL` al inicio: **lo setea el propio SP** al resolver la identidad |
| `sessionId` | `audit.user_session` | Id de la sesión validada (refresh, switch, logout). En login no existe aún: `sp_create_session` lo setea con el id recién insertado antes de cualquier mutación posterior |
| `appName` | `audit.app_name` | Constante **`'auth_ws'`** (el servicio ejecutor; la app cliente origen queda derivable vía sesión → tripleta → `app_id`) |
| `action` | `audit.action` | `"<MÉTODO> <ruta>"`, p. ej. `POST /auth/sessions/switch` |
| `ipAddress` | `audit.ip_address` | `request.ip` (con `trustProxy`) |
| `requestId` | `audit.stack_trace` | `request.id` de Fastify — correlaciona logs del servicio con `audit.event_log` |

Dónde acaba cada cosa:

- `audit.event_log` guarda los 6 valores (`app_user_id`, `app_session_id`,
  `app_name`, `app_action`, `ip_address`, `stack_trace`).
- Las columnas de control de fila (`created_by`/`updated_by`/`deleted_by`)
  solo usan `audit.user_id`. **La sesión NO se persiste a nivel de fila**:
  la fila dice *quién*; el event log dice *quién, desde qué sesión, app,
  acción e IP*.
- Recordatorio duro: `auth.fn_enforce_user_protection()` trata
  `audit.user_id` NULL como **DENY** sobre usuarios protegidos. Contexto
  ausente no solo deja auditoría coja — rompe operaciones.

---

## 6. Tokens

| Token | Forma | Reglas |
|---|---|---|
| **Access** | JWT, TTL por cascada §1.3 | Claims: `sub` (user_id), `acu` (app_customer_user_id), `customer_id`, `app_id`, `sid` (`app_customer_user_sessions.id`), `iat`, `exp`. Firmado **siempre con Ed25519** con la clave del par cliente-app (`customer_apps.access_token_signing_key_encrypted`, descifrada aquí). La **privada nunca sale de `auth_ws`** (único firmador); la **pública** se publica como **JWKS** (`GET /auth/.well-known/keys`, formato JWK) para que cualquier resource server valide localmente y **no pueda emitir** (decisión #18). **No se usa HS256** (simétrica = capacidad de forjar). `sid` deja a los resource servers poblar `audit.event_log.app_session_id` (vía GUC `audit.user_session`) sin tocar BD — atribución de auditoría, no enforcement de revocación; estable entre refreshes de la misma sesión, cambia en `switch` |
| **Refresh** | Opaco, 256 bits CSPRNG, base64url | A BD viaja **solo** `sha256(token)`. Rotación encadenada vía `previous_session_token_hash`. Reuso de hash rotado = robo → revocar cadena. Transporte: cookie `httpOnly; Secure; SameSite=Strict; Path=/auth/sessions` |
| **Ticket** | JWT ~5 min, firmado con clave **de plataforma** (`PLATFORM_TICKET_KEY`, no de tenant) | Claims: `sub`, `app_id`, `purpose` (`tenants` \| `two-factor` \| `change-password`), `jti`. Un solo canje: el SP de canje registra/verifica el `jti`. Código 2FA incorrecto **no** invalida el ticket |

El descifrado de `*_encrypted` (claves de firma, secretos TOTP) ocurre
**únicamente en este servicio**, con caché en memoria de TTL corto (≤5 min)
por `customer_app_id`. Las claves descifradas jamás se loggean ni serializan.

---

## 7. Respuestas y errores

- **Errores de negocio esperables = respuesta tipada con estatus explícito**,
  nunca excepción (decisión #19 del raíz). El estatus y los textos salen del
  **catálogo de mensajes** (`auth_v1.messages.ts` — en código a propósito:
  debe resolver sin BD; i18n por `Accept-Language`, hoy `en`/`es`): todo
  `kind: 'invalid'` lleva `message = { code, messageForClient,
  messageForDeveloper, httpStatusCode }` y la route responde con ese
  `httpStatusCode` (`sendStep`).
- **La opacidad la garantiza la uniformidad, no el estatus**: credenciales
  malas, usuario inexistente, usuario bloqueado y usuario sin empresas en la
  app devuelven el MISMO `ERR_LOGIN_INVALID` (401) con cuerpo idéntico — en
  CUALQUIER paso del flujo (login, two-factor, change-password) — y **misma
  latencia aproximada** (verificar argon2id contra un hash dummy cuando el
  usuario no existe). 400 solo para el código 2FA incorrecto
  (`ERR_2FA_INVALID_CODE`: no filtra existencia, ya exige un ticket válido);
  401 `ERR_TICKET_INVALID` para ticket inválido/expirado. Los códigos que
  filtrarían estado de cuenta (`ERR_LOGIN_LOCKED`, `ERR_NO_TENANTS`,
  `ERR_TENANT_INACTIVE`) existen en el catálogo para usos internos/futuros:
  está **prohibido** conectarlos al flujo de login.
- `POST /auth/password-reset/request` responde **202 siempre**.
- Errores de validación (`VerificationError` de structure-verifier) → 400
  con `{ errors: [{ instancePath, message }] }` vía el error handler global.
- Errores inesperados → 500 opaco `{ error: 'internal', requestId }`; el
  detalle solo a logs. Nunca tragar errores en silencio.
- Logging: `pino` (el de Fastify) con `requestId`. **Prohibido** loggear
  contraseñas, tokens, tickets, hashes, claves o cuerpos de auth.

## 8. Contrato de endpoints (espejo de §2.2 del raíz)

| Endpoint | Body | Respuesta |
|---|---|---|
| `POST /auth/login` | `{ appCode, identifier, password, deviceIdentifier, deviceName? }` | 200 `{ kind: 'two-factor', ticket, method }` \| 200 `{ kind: 'change-password', ticket }` \| 200 `{ kind: 'tenants', ticket, tenants: [{id, name}] }` \| 401 `{ kind: 'invalid', message }` (opaco) |
| `POST /auth/two-factor` | `{ ticket, code }` | mismas variantes; `invalid` según catálogo: 400 código incorrecto (ticket sigue vivo) · 401 ticket inválido/expirado. `code` acepta TOTP (6 dígitos) o código de recuperación |
| `POST /auth/change-password` | `{ ticket, newPassword }` | mismas variantes y estatus: tras el cambio sigue el flujo (`two-factor` si el usuario tiene 2FA, si no `tenants`) |
| `POST /auth/sessions` | `{ ticket, customerId }` | 200 `{ accessToken, expiresIn, user: {id, name(alias), email}, tenant, tenants, permissions: string[] }` + cookie refresh · 401 `{ error: 'invalid' }` (opaco) |
| `POST /auth/sessions/refresh` | — (cookie) | igual que crear sesión (permisos refrescados) |
| `POST /auth/sessions/switch` | `{ customerId }` (access vigente) | igual que crear sesión, en la nueva empresa |
| `POST /auth/sessions/verify` | — (access en `Authorization: Bearer`) | 200 SIEMPRE `{ valid, claims }` — introspección de prueba (firma + vigencia + issuer), no frontera de seguridad |
| `DELETE /auth/sessions/current` | — | 204; revoca (`inactive` + `revoked_at`) |
| `POST /auth/password-reset/request` | `{ identifier }` | 202 siempre |
| `POST /auth/password-reset/confirm` | `{ token, newPassword }` | 204; revoca sesiones del usuario |
| `GET /auth/.well-known/keys` | — | **JWKS** (RFC 7517): claves públicas Ed25519 en formato JWK (`kty`/`crv`/`x`/`kid`/`alg`/`use` + `appCode`), cacheable |

Cualquier cambio aquí debe reflejarse en §2.2 del CLAUDE.md raíz y en
`base_project/src/app/core/auth/data/auth.gateway.ts` (y viceversa).

---

## 9. Configuración (env)

Validada al boot en `config.ts` con structure-verifier; si falta algo el
proceso **no arranca**.

| Variable | Uso |
|---|---|
| `DATABASE_URL` | Conexión como `role_auth_service` |
| `PLATFORM_MASTER_KEY` | AES-256-GCM de campos `*_encrypted` (32 bytes, base64) |
| `PLATFORM_TICKET_KEY` | Firma del ticket de login |
| `PORT` / `HOST` | Servicio (default 3001) |
| `COOKIE_DOMAIN` | Dominio de la cookie de refresh (opcional) |
| `COOKIE_SECURE` | default `true`; `false` SOLO en desarrollo local sin HTTPS |
| `LOG_LEVEL` | pino |

Secretos solo por env (o gestor de secretos del despliegue). Nunca en el
repo, nunca en defaults.
