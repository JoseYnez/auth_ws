# Documentación técnica — Servicio de autenticación (`auth_ws`)

> Generada el 2026-07-19 a partir del código fuente de `auth_ws/` y los scripts de
> `db/` (00..08/99). Complementa (no sustituye) a [CLAUDE.md](../CLAUDE.md) y al
> [CLAUDE.md raíz](../../CLAUDE.md), que siguen siendo la fuente de verdad
> normativa. Cobertura: arquitectura del servicio, funcionamiento de cada tabla
> de la BD, procedures, seguridad, auditoría y reglas de negocio.

---

## 1. Visión general

`auth_ws` es la **API de autenticación y permisos** de una plataforma de
identidad **multitenant y multi-app**: muchas aplicaciones cliente (consola
admin, ERP, residguard, futuras) delegan en ella el login, las sesiones y la
resolución de permisos. Es el **único emisor, rotador y revocador de tokens**
de la plataforma; ningún otro servicio firma tokens.

| Pieza | Elección |
|---|---|
| Runtime | Node.js LTS + TypeScript estricto |
| HTTP | Fastify ≥ 4 (`trustProxy: true`) |
| Validación | `structure-verifier` (entrada Y salida, `strictMode`) |
| BD | PostgreSQL 16, `pg`, usuario `role_auth_service` (cero privilegios de tabla) |
| Hash de contraseñas | argon2id (OWASP 2024: 19 MiB, timeCost 2, parallelism 1) |
| JWT | `jose` — firma EdDSA/Ed25519; JWKS público |
| Cifrado en reposo | AES-256-GCM con `PLATFORM_MASTER_KEY` |

El servicio es **stateless**: todo estado vive en la BD o en el propio token.
Cualquier instancia atiende cualquier request (con matices en los contadores en
memoria, ver §8.5).

### 1.1 Principios rectores

1. **Regla de oro de acceso**: un usuario abre sesión en (cliente, app) solo si
   los cuatro niveles están activos y vigentes: `auth.users` ∧
   `core.customer_users` ∧ `core.customer_apps` ∧ `auth.app_customer_users`.
   "Vigente" = `status='active'` y `now()` dentro de `[starts_at, expires_at)`.
   **Nunca** se usa `deleted_at` como criterio.
2. **Respuestas opacas**: credenciales inválidas, usuario inexistente, usuario
   bloqueado y usuario sin empresas devuelven exactamente la misma respuesta
   (`ERR_LOGIN_INVALID`, 401, cuerpo idéntico, latencia equiparada).
3. **Firma asimétrica universal**: solo `auth_ws` posee claves privadas
   (Ed25519); los resource servers validan con la pública (JWKS) y no pueden
   emitir. HS256 está prohibido.
4. **Cero SQL directo**: `role_auth_service` no tiene privilegios de tabla;
   toda interacción con la BD pasa por procedures `SECURITY DEFINER`.
5. **Auditoría estructural**: es imposible ejecutar SQL sin contexto de
   auditoría — el pool no se expone y `withTransaction` setea los GUCs siempre.

---

## 2. Modelo de negocio

| Concepto | Tabla | Qué es |
|---|---|---|
| App | `core.apps` | Cada aplicación servida por la plataforma |
| Cliente (tenant) | `core.customers` | Empresa que contrata apps. Sin slug: referencias por UUID |
| Usuario | `auth.users` | Identidad **global y única** (username y email únicos, citext). No pertenece a ningún cliente |
| Membresía | `core.customer_users` | Usuario ∈ cliente (multipertenencia). Su `name` = alias del usuario dentro del cliente |
| Acceso ("tripleta") | `auth.app_customer_users` | (cliente, app, usuario). `name` = override opcional del alias por app |
| Sesión | `auth.app_customer_user_sessions` | Cuelga de la tripleta, nunca del usuario. Una sesión = un dispositivo en una empresa en una app |

Las apps muestran siempre el alias en cascada
`COALESCE(tripleta.name, membresía.name)`, nunca `users.full_name`.

### 2.1 Cadena de relaciones

```
auth.users ──┐
             ├──< core.customer_users (customer_id, user_id) UNIQUE ──┐
core.customers ──< core.customer_apps (customer_id, app_id) UNIQUE ───┤
core.apps ───────┘                                                    │
                                                                      ▼
                 auth.app_customer_users ("tripleta": customer_id, app_id, user_id)
                   FK (customer_id, app_id)  → core.customer_apps
                   FK (customer_id, user_id) → core.customer_users
                                          │
          ┌───────────────────────────────┼───────────────────────────────┐
          ▼                               ▼                               ▼
app_customer_user_sessions     app_customer_user_roles       app_customer_user_permissions
   (sesiones/dispositivos)        (roles asignados)             (permisos directos/materializados)
```

`auth.roles` y `auth.permissions` cuelgan de `core.apps`. Las tablas de
credenciales/2FA/tokens cuelgan directamente de `auth.users`.

### 2.2 Herencia de configuración (cascada COALESCE)

`max_sessions`, `access_token_ttl_minutes`, `refresh_token_ttl_minutes`,
`max_failed_login_attempts` y `login_lockout_minutes` se resuelven en tres
niveles — NULL significa "hereda del padre":

```sql
COALESCE(app_customer_users.x, customer_apps.x, apps.x)
```

Fallbacks aplicados en la capa API de la BD cuando toda la cascada es NULL:
**3** intentos fallidos, **15** min de lockout, **3** sesiones, **480** min de
refresh. En la tabla `core.apps`, `max_failed_login_attempts` (3) y
`login_lockout_minutes` (15) ya son NOT NULL con default.

---

## 3. Base de datos — convenciones transversales

Definidas en `db/00_base_infrastructure.sql` y aplicadas a todas las tablas de
negocio.

### 3.1 Columnas de control (patrón común)

Todas las tablas llevan: `created_at/created_by`, `updated_at/updated_by`,
`deleted_at/deleted_by`, `status public.record_status`. Las gestiona el trigger
`util.fn_set_audit_fields()` (BEFORE INSERT/UPDATE):

- El **actor** se lee del GUC `audit.user_id`; el caller **no puede forjar**
  `created_by/created_at` (el trigger los sobreescribe).
- UPDATE con detección de no-op: si solo cambian columnas de control no se
  refresca `updated_at/by`.
- **Soft delete**: pasar `status → 'deleted'` puebla `deleted_at/by`
  automáticamente; salir de `'deleted'` los limpia. `deleted_at` es
  informativo — **jamás** criterio de negocio.

### 3.2 Vigencia

Tablas con ventana de validez usan `starts_at` (default `now()`) +
`expires_at` (NULL = sin caducidad) con CHECK `expires_at > starts_at`.
Registro vigente = `status='active' AND now() >= starts_at AND (expires_at IS
NULL OR now() < expires_at)`.

### 3.3 PKs y tipos

- PK siempre `id UUID DEFAULT util.uuid_v7()` — UUID v7 (RFC 9562), ordenable
  por tiempo.
- Identificadores de negocio en `citext` (case-insensitive): usernames, emails,
  códigos de app/permiso/rol, nombres de cliente.

### 3.4 Enums

| Tipo | Valores |
|---|---|
| `public.record_status` | `active`, `inactive`, `deleted` |
| `auth.user_type` | `system`, `admin`, `customer` |
| `auth.credential_type` | `password` (extensible) |
| `auth.two_factor_method_type` | `sms`, `email`, `totp`, `authenticator_app` (solo TOTP al lanzamiento) |
| `auth.verification_purpose_type` | `email_verification`, `phone_verification`, `password_reset`, `two_factor_sms_challenge`, `two_factor_email_challenge`, `invitation`, `login_ticket` |
| `auth.role_scope_type` | `platform_only`, `system_default`, `customer_custom` |
| `auth.permission_action_type` | `read`, `create`, `update`, `delete`, `execute` |
| `auth.permission_assignment_source_type` | `role`, `manual` |
| `core.billing_cycle_type` | `monthly`, `quarterly`, `semi_annual`, `annual` |
| `audit.operation_type` | `INSERT`, `UPDATE`, `DELETE` |

---

## 4. Tablas — schema `core`

### 4.1 `core.customers` — clientes (tenants)

Raíz de la jerarquía multitenant.

| Columna | Significado |
|---|---|
| `name` citext | Nombre corto **único** (UNIQUE parcial `WHERE status != 'deleted'`) |
| `legal_name` | Razón social |
| `contact_email/phone`, `tax_id` | Datos de contacto/fiscales |
| `max_users` INT | Tope de miembros contados (NULL = ilimitado). Enforced por trigger TOCTOU-safe (`FOR UPDATE`) |
| `starts_at/expires_at` | Vigencia del cliente (nivel 1 de la regla de oro) |

### 4.2 `core.apps` — aplicaciones

Registro de apps y **fondo de la cascada de configuración**.

| Columna | Significado |
|---|---|
| `code` citext | Identificador único de la app (`admin-app`, `residguard-app`…) — es el `appCode` del login |
| `name`, `version`, `description` | Metadatos |
| `max_sessions` SMALLINT | Sesiones simultáneas por tripleta (nullable) |
| `access_token_ttl_minutes` / `refresh_token_ttl_minutes` | TTLs (nullable) |
| `max_failed_login_attempts` | Default **3** (NOT NULL) |
| `login_lockout_minutes` | Default **15** (NOT NULL) |

Trigger notable: al insertar una app se auto-crea su rol `superadmin`
(`platform_only`, `grants_all_permissions=true`).

### 4.3 `core.customer_apps` — contratación cliente↔app

Nivel intermedio de herencia y **hogar de las claves de firma**.

| Columna | Significado |
|---|---|
| `customer_id`, `app_id` | Par UNIQUE (target del FK compuesto de la tripleta); write-once por trigger |
| Overrides de config | Las 5 columnas de la cascada, todas nullable (NULL = hereda de `apps`) |
| `access_token_signing_key_encrypted` | **Clave Ed25519 del par cliente-app**, cifrada AES-256-GCM. Solo `auth_ws` la descifra. Redactada en auditoría |
| `refresh_token_signing_key_encrypted` | Reservada (el refresh actual es opaco, no firmado). Redactada y oculta a la consola |

### 4.4 `core.customer_users` — membresías

Usuario ∈ cliente (definida en `03_auth_tables.sql` por dependencias).

| Columna | Significado |
|---|---|
| `customer_id`, `user_id` | Par UNIQUE, write-once |
| `name` | **Alias del usuario dentro del cliente** (base de la cascada de alias) |
| `is_counted_for_user_limit` | Si cuenta para `customers.max_users` (default true) |
| `starts_at/expires_at` | Vigencia (nivel 2 de la regla de oro) |

Trigger `fn_validate_customer_user_limit`: bloquea inserciones/activaciones que
superen `max_users`, y bajadas de `max_users` por debajo del conteo activo.

### 4.5 `core.customer_billing_profiles` — facturación

Perfiles de facturación por cliente (N por cliente, uno default). Constraints:
`billing_day` 1–28, moneda ISO 4217 (`^[A-Z]{3}$`), país ISO 3166
(`^[A-Z]{2}$`), UNIQUE parcial de un default activo por cliente.

---

## 5. Tablas — schema `auth`

### 5.1 `auth.users` — identidad global

Una fila por persona (o cuenta de servicio). No pertenece a ningún cliente.

| Columna | Significado |
|---|---|
| `username`, `email` citext | Únicos (UNIQUE parcial `WHERE status != 'deleted'`) — ambos sirven como `identifier` del login |
| `full_name`, `phone`, `birthday`, `profile_photo_url` | Perfil |
| `user_type` | `system` / `admin` (staff plataforma) / `customer`. **Write-once** (trigger anti-escalada) |
| `email_verified_at`, `phone_verified_at`, `verified_at` | Verificaciones independientes |
| `two_factor_enabled` + `two_factor_method` | CHECK de consistencia: habilitado ⇔ método no NULL |
| `is_protected` | Usuarios protegidos (p. ej. `system`) |
| `starts_at/expires_at` | Vigencia (nivel del usuario en la regla de oro) |

**Triggers de seguridad**:

- `fn_validate_user_type_immutable` — `user_type` no puede cambiar por UPDATE.
- `fn_enforce_user_insert_privileges` — solo staff crea usuarios
  `system`/`admin` o protegidos (con excepción de bootstrap cuando aún no
  existe staff).
- `fn_enforce_user_protection` — UPDATE/DELETE sobre filas protegidas exige
  actor staff **activo**; `audit.user_id` NULL = **DENY**; hard-DELETE de
  cualquier usuario prohibido a no-staff (se fuerza soft delete).

### 5.2 `auth.user_credentials` — credenciales

Una credencial activa por `(user_id, credential_type)` (UNIQUE parcial).

| Columna | Significado |
|---|---|
| `secret_hash` | Hash PHC. **CHECK whitelist de prefijo**: `^\$(argon2id\|argon2i\|argon2d\|2a\|2b\|2y\|scrypt\|pbkdf2-sha256\|pbkdf2-sha512)\$` y longitud ≥ 50 — rechaza texto plano y hashes truncados. Redactado en auditoría |
| `must_change_secret` | Fuerza el flujo `change-password` en el login |
| `failed_login_attempts`, `locked_until_at` | Estado de lockout (umbral por cascada §2.2) |
| `expires_at` | Caducidad de la credencial (tratada como `must_change_secret` en el login) |
| `last_used_at` | Último login exitoso |

Hard-delete bloqueado a no-staff por trigger.

### 5.3 `auth.app_customer_users` — la tripleta

El nudo central del modelo: acceso de un usuario a una app dentro de un
cliente. FKs **compuestos** que garantizan integridad de la cadena:
`(customer_id, app_id) → customer_apps` y `(customer_id, user_id) →
customer_users`; terna UNIQUE y write-once.

| Columna | Significado |
|---|---|
| `name` | Override del alias por app (NULL = hereda el de la membresía) |
| Overrides de config | Las 5 columnas de la cascada (nivel hoja) |
| `starts_at/expires_at` | Vigencia (nivel 4 de la regla de oro) |

### 5.4 `auth.app_customer_user_sessions` — sesiones

Una fila por dispositivo/navegador, colgada de la tripleta.

| Columna | Significado |
|---|---|
| `session_token_hash` | `sha256(refresh_token)` — **el token crudo jamás toca la BD**. UNIQUE. Redactado en auditoría |
| `previous_session_token_hash` | Encadena la rotación (traza informativa + detección de reuso) |
| `device_identifier`, `device_name`, `device_info_json` | Identificación del dispositivo (el identifier lo genera y persiste el cliente) |
| `ip_address` INET, `user_agent` | Contexto de la última operación |
| `started_at`, `expires_at`, `revoked_at` | Ciclo de vida |

**Estados**: `active` (válida) · `inactive` (revocada — logout, switch,
rotación, desplazada por `max_sessions`; CHECK exige `revoked_at`) · `deleted`
(purga GC). Validez = `status='active' AND expires_at > now()`,
exclusivamente.

GC: `auth.sp_purge_expired_sessions(grace_minutes)` marca `deleted` las
activas ya expiradas (job programado, no per-request).

### 5.5 `auth.user_verification_tokens` — tokens one-shot

Tokens efímeros de flujos asíncronos; solo se persiste `sha256(token)`
(UNIQUE, ≥32 chars).

| Columna | Significado |
|---|---|
| `purpose` | `password_reset`, `invitation`, `login_ticket` (canje one-shot del jti del ticket de login), verificaciones, y los challenges OTP 2FA `two_factor_{sms,email,whatsapp}_challenge` (hash `sha256(userId:purpose:código)`, TTL 10 min, **un challenge vivo por usuario+purpose** — la emisión hace DELETE físico del previo, excepción documentada en db/CLAUDE.md §8) |
| `token_hash` | UNIQUE — el ON CONFLICT de este índice implementa el "one-shot" del ticket |
| `expires_at`, `consumed_at` | Vigencia y canje (NULL = no usado) |
| `ip_address`, `user_agent` | Contexto de emisión |

Los TOTP **no** usan esta tabla (secreto persistente, ver 5.6). GC:
`sp_purge_expired_verification_tokens` (los consumidos se conservan como
evidencia).

### 5.6 `auth.user_two_factor_secrets` — secretos TOTP

Secretos persistentes de 2FA por autenticador. CHECK: solo métodos
`totp`/`authenticator_app`. UNIQUE parcial: un secreto por usuario+método
(rotar = soft-delete del anterior + fila nueva).

| Columna | Significado |
|---|---|
| `secret_encrypted` | Seed base32 cifrado **en el servicio** (AES-256-GCM); el plaintext nunca llega a la BD. Redactado en auditoría |
| `activated_at` | NULL = enrolado sin confirmar; se sella al validar el primer código |
| `last_used_at` | Último uso |

### 5.7 `auth.user_two_factor_recovery_codes` — códigos de recuperación

Lote impreso una sola vez al enrolar 2FA; cada código permite un bypass
exactamente una vez. Solo `sha256(código normalizado)` (mayúsculas, sin
guiones). `consumed_at` NULL = usable. Los consumidos **no** se borran
(evidencia); regenerar el lote soft-borra los anteriores.

---

## 6. Autorización (RBAC)

**Filosofía**: el primitivo es el permiso; los roles son agregaciones puras.
Los permisos efectivos son la **unión** de todo lo asignado — no existe
"revocar heredado" (más roles ⇒ nunca menos permisos). Las excepciones se
modelan creando otro rol.

### 6.1 `auth.permissions` — catálogo por app

`code` citext canónico con puntos (`orders.refund`), `resource` prefijo
agrupador (CHECK: `resource` debe ser prefijo estricto de `code`),
`action_type` ∈ read/create/update/delete/execute. UNIQUE `(app_id, code)`.
El catálogo lo define el publicador de la app; los clientes lo consumen.

### 6.2 `auth.roles`

| Columna | Significado |
|---|---|
| `scope` | `platform_only` (staff) · `system_default` (defaults del publicador) · `customer_custom` (creados por el cliente) |
| `customer_id` | CHECK: NULL ⇔ scope platform/system; NOT NULL ⇔ customer_custom |
| `parent_role_id` | Herencia **aditiva de un solo nivel**: solo customer_custom hereda, solo de un system_default sin padre |
| `grants_all_permissions` | Comodín (el rol `superadmin` auto-creado por app); CHECK: el comodín no hereda ni admite filas en `role_permissions` |

### 6.3 Asignaciones sobre la tripleta

- `auth.role_permissions` — grants N:N rol↔permiso (misma app en ambos lados).
- `auth.app_customer_user_roles` — roles por tripleta, con `expires_at` por
  asignación. Trigger de validación: rol de la misma app; `platform_only`
  exige actor staff; `customer_custom` exige mismo cliente. Trigger de
  limpieza: al revocar una asignación se soft-borran sus permisos
  materializados (anti "ghost grants").
- `auth.app_customer_user_permissions` — permisos directos por tripleta.
  `assigned_via`: `manual` (grant directo, `source_role_id` NULL) o `role`
  (materializado, `source_role_id` NOT NULL); CHECK de consistencia y UNIQUEs
  parciales distintos por procedencia.

### 6.4 Resolución

- `auth.fn_get_effective_permissions(acu_id)` — la tripleta solo resuelve si
  **todos** sus ancestros están activos y vigentes (users, customers, apps,
  customer_apps, customer_users, app_customer_users). Con comodín asignado:
  expande a todo el catálogo activo de la app (short-circuit). Sin comodín:
  unión de permisos de roles (propios + del padre single-level) + directos,
  respetando `expires_at` por asignación.
- `auth.fn_has_permission(acu_id, code)` — wrapper EXISTS; es la primitiva de
  **enforcement en el servidor** de los resource servers. El frontend usa la
  lista plana solo para UI, nunca como frontera de seguridad.

---

## 7. API de BD (procedures `SECURITY DEFINER`)

`role_auth_service` solo tiene `GRANT EXECUTE` sobre estos objetos (el GRANT
vive junto a cada definición). Resultados por `INOUT p_result JSONB` en
camelCase; el campo interno `reason` nunca llega al cliente HTTP. Los SPs
añaden al contexto lo que el servicio no conoce aún: `audit.user_id` al
resolver la identidad y `audit.user_session` al crear/rotar la sesión.

### 7.1 Flujo de login (`06_auth_service_api.sql`)

| Objeto | Lógica |
|---|---|
| `sp_login(app_code, identifier)` | Resuelve app por `code` y usuario por username **o** email; setea `audit.user_id`; valida credencial activa y lockout. Devuelve `secretHash` (la verificación argon2id ocurre en Node — la BD no tiene argon2), `mustChangeSecret` (flag o credencial caducada), flags 2FA, empresas accesibles y umbrales de lockout (de `core.apps`: en credenciales aún no hay cliente elegido). Cualquier fallo → `{ok:false}` opaco |
| `sp_register_login_attempt(user_id, app_id, success)` | Éxito: resetea contador y sella `last_used_at`. Fallo: incrementa (reinicia si el lockout previo venció) y al llegar al umbral aplica `locked_until_at = now() + lockout` |
| `sp_consume_ticket_jti(user_id, jti_hash, expires_at)` | **One-shot** del ticket: INSERT del `sha256(jti)` como `login_ticket` consumido, `ON CONFLICT DO NOTHING`; el segundo canje devuelve `ok:false` |
| `sp_create_session(...)` | Consume el jti + `sp_open_session` (interno): valida la tripleta (regla de oro), resuelve `max_sessions`/TTL por cascada, **revoca las sesiones más antiguas** si se alcanza el tope (mantiene `max-1` vivas, `FOR UPDATE` — el login nunca se rechaza por tope), inserta la sesión y devuelve el payload completo |
| `sp_refresh_session(hash, new_hash, ip, ua)` | **Rotación encadenada** con `FOR UPDATE`. Si el hash no corresponde a una sesión activa: detecta **reuso** (¿existe un descendiente vivo con `previous_session_token_hash = hash`? → robo: revoca la cadena y devuelve `token-reuse-detected`). Revalida los 4 niveles (el acceso pudo revocarse tras emitir); si ya no aplica, revoca la sesión. En éxito: rota el hash, encadena el anterior, renueva `expires_at` (ventana deslizante) |
| `sp_switch_session(hash, new_customer_id, new_hash, ip, ua)` | Cambio de empresa sin re-login: revoca la sesión actual y abre una nueva contra la otra tripleta reutilizando los datos de dispositivo |
| `sp_revoke_session(hash)` | Logout: `inactive` + `revoked_at`. **Idempotente** |
| `sp_change_password(user_id, jti_hash, jti_exp, new_hash)` | Cambio obligatorio con ticket: consume el jti, fija el hash, limpia lockout, **revoca todas las sesiones vivas** del usuario. Devuelve flags 2FA para el paso siguiente |
| `sp_request_password_reset(identifier, token_hash, ttl, ip, ua)` | Emite token `password_reset` (60 min); usuario inexistente → `ok:false` sin alterar la respuesta HTTP (202 siempre). Devuelve email/nombre para el correo |
| `sp_confirm_password_reset(token_hash, new_hash)` | Consume el token (`FOR UPDATE`, solo tras confirmar el cambio), fija el hash, limpia lockout y revoca **todas** las sesiones del usuario |
| `sp_consume_recovery_code(user_id, code_hash)` | Canje one-shot del código de recuperación 2FA (no se borra: evidencia) |
| `fn_get_two_factor_secret(user_id)` | Secreto TOTP cifrado, solo si activo y **confirmado** (`activated_at NOT NULL`) |
| `fn_get_accessible_tenants(user_id, app_id)` | Empresas accesibles (intersección de la regla de oro) — usada en los pasos 2FA/change-password |
| `fn_get_signing_key(customer_id, app_id)` / `fn_list_signing_keys()` | Claves de firma cifradas del par / de todos los pares (para verificar en switch y para el JWKS) |
| `sp_issue_two_factor_challenge(user_id, purpose, code_hash, ttl, ip, ua)` | Emite el challenge OTP de canal: borra el previo del par (user, purpose) e inserta el nuevo. Devuelve también email/phone (contacto de envío) |
| `sp_consume_two_factor_challenge(user_id, purpose, code_hash)` | Canje one-shot; código incorrecto y expirado son indistinguibles (`ok:false`) |
| `fn_get_two_factor_channel_info(user_id)` | Método 2FA activo + contacto (normaliza `authenticator_app`→`totp`); NULL sin 2FA activo |

Internos sin GRANT (solo invocables desde los públicos):
`sp_open_session` (núcleo compartido de crear/refresh/switch) y
`fn_build_session_payload` (ensambla sessionId, TTLs por cascada, alias por
cascada, tenant, tenants y permisos efectivos).

### 7.2 Onboarding y 2FA (`08_auth_onboarding_api.sql`)

| Objeto | Lógica |
|---|---|
| `sp_consume_invitation_token(token_hash, new_secret_hash)` | One-shot del token `invitation`: rechaza si ya existe credencial (`credential-exists`), crea la **primera** credencial de password y sella `email_verified_at` (aceptar el link prueba titularidad del correo) |
| `sp_enroll_two_factor(user_id, secret_encrypted, recovery_hashes[])` | Enrola/rota TOTP: soft-borra el secreto y códigos anteriores, inserta el nuevo **sin activar**; descarta challenges de canal pendientes (exclusión mutua de enrolamientos) |
| `sp_enroll_two_factor_channel(user_id, method, phone, recovery_hashes[], code_hash, ttl, ip, ua)` | Enrola un método de canal: fija el teléfono si se aporta (resetea su verificación), regenera recovery codes, descarta un secreto TOTP pendiente y emite el challenge. `phone-required` si sms/whatsapp sin teléfono |
| `fn_get_pending_two_factor_secret(user_id)` | Secreto TOTP enrolado sin confirmar |
| `fn_get_pending_two_factor_enrollment(user_id)` | Qué enrolamiento hay pendiente: `{method:'totp',secretEncrypted}` \| `{method:canal}` \| NULL |
| `sp_activate_two_factor(user_id, method, code_hash)` | Activa el 2FA por método: totp sella `activated_at`; los canales consumen el challenge en la misma transacción y **sellan la titularidad del contacto** (`phone_verified_at`/`email_verified_at`) |

### 7.3 API de consola (`07_platform_console_api.sql`, para `admin_ws`)

`sp_ensure_invited_user` (alta idempotente por email),
`sp_issue_invitation_token` (un token vivo por usuario; rechaza cuentas ya
credencializadas), `sp_revoke_customer_user_sessions` y
`sp_revoke_access_sessions`. GRANT a `role_platform_console`; a diferencia de
la API de auth, **no** sobreescriben `audit.user_id` (el actor es el staff que
`admin_ws` ya seteó).

---

## 8. El servicio `auth_ws`

### 8.1 Capas (estándar de endpoint)

```
routes (HTTP, verifiers, AuditContext, cookies)
  → controller (caso de uso; sin SQL, sin tipos de Fastify)
    → repository (CALL/SELECT a procedures; recibe tx)
      → withTransaction (única puerta a la BD: BEGIN + 6 GUCs + COMMIT/ROLLBACK)
```

Reglas: todo body/params/query pasa por un verifier `strictMode` (propiedad no
declarada = rechazo); las **respuestas también se declaran** (el serializer
garantiza que jamás se filtre un campo no contratado); un endpoint = una
transacción; URLs kebab-case, JSON camelCase, BD snake_case (mapeo solo en el
repository).

### 8.2 Flujo de autenticación por pasos

```
credenciales ──► (change-password si must_change_secret)
             ──► (2FA TOTP si el usuario lo tiene)
             ──► selección de empresa ──► sesión
```

1. **Credenciales** (`POST /auth/login`): `appCode` + `identifier` (username o
   email) + `password` + `deviceIdentifier`. `sp_login` entrega el hash; la
   verificación argon2id ocurre en Node; `sp_register_login_attempt` registra
   el resultado. Si supera: se emite un **ticket** (JWT ~5 min, un solo canje)
   con la lista de empresas. Si el usuario no existe se verifica contra un
   **hash dummy** para igualar la latencia.
2. **2FA** (`POST /auth/two-factor`): verifica el código de 6 dígitos según el
   **método del usuario** — TOTP (RFC 6238, HMAC-SHA1, paso 30 s, con
   anti-replay) o el **código OTP de canal** (whatsapp/sms/email, decisión
   #20) enviado al responder el login (`destination` enmascarado en la
   respuesta; reenvío vía `/auth/two-factor/resend`, 3 por ticket con
   cooldown de 60 s, cada reenvío invalida el código anterior). También se
   aceptan códigos de recuperación (cualquier método). Código incorrecto
   **no** invalida el ticket (reintentable, 400) hasta el tope de 5 intentos
   por ticket — entonces el jti se quema en BD y el ticket muere en todo el
   clúster.
3. **Empresa** (`POST /auth/sessions`): canjea ticket + `customerId`. Si el
   usuario tiene una sola empresa, la app entra directo sin selector. La
   "última empresa" la recuerda el cliente (preselección visual).

### 8.3 Tokens

| Token | Forma | Reglas |
|---|---|---|
| **Access** | JWT EdDSA/Ed25519, TTL por cascada | Claims: `sub` (user_id), `acu` (tripleta), `customer_id`, `app_id`, `sid` (sesión), `iat/exp`, issuer `auth_ws`, header `kid`. Firmado con la clave del **par cliente-app** (descifrada de `customer_apps`, caché en memoria ≤5 min). El tenant viaja SIEMPRE como claim. `sid` sirve para atribución de auditoría en los resource servers (no enforcement de revocación); estable entre refreshes, cambia en switch |
| **Refresh** | Opaco, 256 bits CSPRNG, base64url | A BD solo `sha256(token)`; rotación encadenada; **reuso de un hash rotado = robo → revocar la cadena**. Transporte: cookie **por app** `auth_refresh__<appCode>` (`httpOnly; Secure; SameSite=Strict; Path=/auth/sessions`) |
| **Ticket** | JWT HS256 ~5 min con clave de **plataforma** (`sha256(PLATFORM_TICKET_KEY)`) | Claims: `sub`, `app_id`, `app_code`, `purpose` (`tenants`\|`two-factor`\|`change-password`), `jti`, `did/dna` (dispositivo). Un solo canje (jti en BD). Stateless |
| **Enrollment ticket** | JWT de plataforma para el flujo invitación → enrolar 2FA | Emitido por `sp_consume_invitation_token` vía servicio |

#### Cookie de refresh por app (multi-app en un navegador)

Hay **una cookie por app**: `auth_refresh__<appCode>`. Apps distintas conviven
en el mismo navegador con sesiones (y usuarios) independientes. El `appCode`
que el cliente manda en refresh/switch/logout **solo selecciona qué cookie**
leer/escribir; la autoridad es siempre la sesión (tripleta) anclada al token.
Invariante: una cookie `auth_refresh__X` solo contiene sesiones de la app X,
porque solo el servidor la escribe (con el `appCode` del ticket firmado en la
creación, o el de la cookie leída en refresh/switch). `appCode` cumple
`^[A-Za-z0-9._-]{1,64}$` (valida el verifier + guardia en el nombre de la
cookie). La cookie legacy `auth_refresh` jamás se lee y se limpia
automáticamente.

### 8.4 Contrato de endpoints

| Endpoint | Body | Respuesta |
|---|---|---|
| `POST /auth/login` | `{ appCode, identifier, password, deviceIdentifier, deviceName? }` | 200 `{ kind: 'two-factor', method, destination? \| 'change-password' \| 'tenants', ticket, ... }` · 401 opaco. `destination` = destino enmascarado del código de canal |
| `POST /auth/two-factor` | `{ ticket, code }` | mismas variantes; 400 código incorrecto (ticket vivo) · 401 ticket inválido. `code` = TOTP u OTP de canal según el método, o recovery code |
| `POST /auth/two-factor/resend` | `{ ticket }` | 200 `{ destination, remaining, cooldownSeconds }` · 429 cooldown/límite · 400 método sin envío |
| `POST /auth/change-password` | `{ ticket, newPassword }` | mismas variantes (sigue 2FA o tenants) |
| `POST /auth/sessions` | `{ ticket, customerId }` | 200 `{ accessToken, expiresIn, user{id,name(alias),email}, tenant, tenants, permissions[] }` + cookie · 401 opaco |
| `POST /auth/sessions/refresh` | `{ appCode }` + cookie de esa app | igual que crear sesión (permisos refrescados) |
| `POST /auth/sessions/switch` | `{ appCode, customerId }` + access Bearer + cookie | igual, en la nueva empresa |
| `POST /auth/sessions/verify` | — (Bearer) | 200 SIEMPRE `{ valid, claims }` — introspección de prueba, no frontera de seguridad |
| `DELETE /auth/sessions/current` | `?appCode=` (querystring) | 204; idempotente |
| `POST /auth/password-reset/request` | `{ identifier }` | **202 siempre** (opaco) |
| `POST /auth/password-reset/confirm` | `{ token, newPassword }` | 204; revoca todas las sesiones |
| `POST /auth/invitation/accept` | `{ token, newPassword }` | 200 `{ kind: 'enroll-2fa', enrollmentTicket }` |
| `POST /auth/two-factor/enroll` | `{ enrollmentTicket, method, phone? }` | 200 totp: `{ method, secret, otpauthUri, recoveryCodes[] }` (se muestra UNA vez) · 200 canal: `{ method, destination, recoveryCodes[], cooldownSeconds }` · 400 `ERR_PHONE_REQUIRED` |
| `POST /auth/two-factor/enroll/resend` | `{ enrollmentTicket }` | igual que `/auth/two-factor/resend` |
| `POST /auth/two-factor/confirm` | `{ enrollmentTicket, code }` | 200 `{ kind: 'done' }` — para canales, el canje sella `phone/email_verified_at` |
| `GET /auth/.well-known/keys` | — | JWKS (RFC 7517): claves públicas Ed25519 de todos los pares, con `kid` y `appCode`; `cache-control: max-age=3600` |

Los **permisos efectivos van embebidos** en la respuesta de sesión (crear,
refresh, switch) — no en el JWT ni en un endpoint aparte. El cliente los
cachea y los renueva con cada refresh.

### 8.5 Defensas

| Defensa | Mecanismo | Ámbito |
|---|---|---|
| Rate limiting por IP | En memoria por endpoint: login 10/min · two-factor 10/min · change-password 10/min · invitation-accept 10/5min · 2fa-enroll 15/5min · 2fa-confirm 10/min · pwreset-request 5/5min · pwreset-confirm 10/5min → 429 | Por instancia (multi-instancia requiere store compartido) |
| Lockout por cuenta | `failed_login_attempts`/`locked_until_at` en BD; umbral y duración por cascada | Global (BD) |
| Tope de intentos 2FA | 5 códigos incorrectos por ticket → el jti se quema en BD (muere en todo el clúster) | Contador local + kill global |
| Throttle de reenvío OTP | 3 reenvíos por ticket, cooldown 60 s; cada reenvío invalida el código anterior; agotarlos NO quema el jti | Por instancia (más rate limit IP 5/min) |
| Anti-replay TOTP | Un step de 30 s aceptado no se reutiliza (también cubre el código usado al confirmar el enrolamiento) | Por instancia |
| Igualación de tiempos | Verificación argon2id contra hash dummy cuando el usuario no existe | — |
| Opacidad | Cuatro causas indistinguibles → mismo `ERR_LOGIN_INVALID` 401, cuerpo idéntico, en cualquier paso | — |
| Detección de robo de refresh | Reuso de hash rotado → revocación de la cadena | Global (BD) |
| `max_sessions` | Alcanzado el tope se revoca la más antigua (no se rechaza el login) | Global (BD) |

### 8.6 Catálogo de errores (`auth_v1.messages.ts`)

En código a propósito (debe resolver sin BD), i18n por `Accept-Language`
(`en`/`es`). Todo `kind: 'invalid'` lleva
`message = { code, messageForClient, messageForDeveloper, httpStatusCode }` y
la respuesta HTTP usa ese estatus.

| Código | HTTP | Uso |
|---|---|---|
| `ERR_LOGIN_INVALID` | 401 | Las cuatro causas opacas del login, en cualquier paso |
| `ERR_2FA_INVALID_CODE` | 400 | Código 2FA incorrecto o challenge expirado (indistinguibles; ticket sigue vivo) |
| `ERR_2FA_RESEND_COOLDOWN` / `ERR_2FA_RESEND_LIMIT` | 429 | Reenvío en cooldown / reenvíos agotados (el último código sigue vigente) |
| `ERR_2FA_METHOD_NOT_RESENDABLE` | 400 | El método del usuario no envía códigos (totp) |
| `ERR_PHONE_REQUIRED` | 400 | Enrolamiento sms/whatsapp sin teléfono registrado ni aportado |
| `ERR_TICKET_INVALID` | 401 | Ticket inválido/expirado/replayado/quemado |
| `ERR_INVITATION_INVALID` / `ERR_ENROLLMENT_INVALID` | — | Onboarding/enrolamiento 2FA |
| `ERR_LOGIN_LOCKED`, `ERR_NO_TENANTS`, `ERR_TENANT_INACTIVE`, `ERR_SESSION_INVALID`, `ERR_SESSION_EXPIRED` | — | **Prohibido conectarlos al flujo de login** (filtrarían estado de cuenta); existen para usos internos/futuros |
| `ERR_INTERNAL_ERROR` | 500 | Fallback opaco |

Otros errores: validación (`structure-verifier`) → 400 con
`{ errors: [{instancePath, message}] }`; inesperados → 500 opaco
`{ error: 'internal', requestId }`. Prohibido loggear contraseñas, tokens,
tickets, hashes o claves.

### 8.7 Criptografía

| Uso | Implementación |
|---|---|
| Contraseñas | argon2id (19 MiB, t=2, p=1); prefijo PHC whitelisteado por constraint en BD; política: 12–256 chars |
| Cifrado en reposo | AES-256-GCM, formato `v1.<iv>.<tag>.<ciphertext>` (base64url, IV 12 bytes) — versión para rotación de esquema. Cubre claves de firma y secretos TOTP; descifrado SOLO en `auth_ws` |
| Firma de access tokens | Ed25519 por par cliente-app; blob cifrado `{alg:'EdDSA', privateKeyPem(PKCS8), publicKeyPem(SPKI), kid}`; caché descifrada ≤5 min; nunca se loggea |
| Refresh/ticket aleatorios | CSPRNG 256 bits; a BD solo `sha256` |
| TOTP | RFC 6238 HMAC-SHA1, paso 30 s, 6 dígitos, secreto base32 — implementado con `node:crypto`, sin dependencias |

---

## 9. Contexto de auditoría

### 9.1 GUCs (scope transacción)

`withTransaction(ctx, fn)` es la única puerta a la BD: setea con
`set_config(..., true)` los 6 GUCs al abrir cada transacción — el contexto
muere con el COMMIT/ROLLBACK.

| GUC | Contenido en `auth_ws` |
|---|---|
| `audit.user_id` | Identidad global. NULL en login/canjes: **lo setea el propio SP** al resolver la identidad |
| `audit.user_session` | Sesión. La setea `sp_open_session` con el id recién insertado |
| `audit.app_name` | Constante `'auth_ws'` (el servicio ejecutor; la app cliente origen se deriva vía sesión → tripleta → `app_id`) |
| `audit.action` | `"MÉTODO /ruta"` |
| `audit.ip_address` | `request.ip` (con `trustProxy`) |
| `audit.stack_trace` | `request.id` de Fastify (correlación logs ↔ event_log) |

### 9.2 `audit.event_log`

Tabla **particionada por mes** (`PARTITION BY RANGE (occurred_at)`, particiones
auto-creadas en UTC con manejo de carreras) y **append-only** (trigger que
bloquea UPDATE/DELETE de filas; la retención es DROP manual de particiones por
el DBA).

Cada tabla de negocio lleva un trigger AFTER genérico
(`audit.fn_capture_event_log`) que escribe: origen
(`source_schema/table/id`), operación, **diff JSONB** (INSERT: snapshot;
UPDATE: solo campos cambiados, no-op no escribe; DELETE: snapshot), los 6
valores de contexto y datos de la conexión (`db_user`, `txid`).

**Redacción**: los valores sensibles se sustituyen por `"[REDACTED]"` antes de
persistir el diff — `secret_hash`, hashes de sesión, claves de firma cifradas,
`token_hash`, secretos TOTP y códigos de recuperación. La PII (emails,
teléfonos) NO se redacta: se protege con control de acceso a `event_log`.

**Reparto**: `event_log` guarda el quién/desde qué sesión/app/acción/IP; las
columnas de fila (`created_by/updated_by/deleted_by`) solo guardan el quién.
La sesión no se persiste a nivel de fila.

---

## 10. Seguridad de la BD (roles, RLS)

| Rol | Privilegios |
|---|---|
| `role_owner` | NOLOGIN; dueño de todos los objetos; solo migraciones |
| `role_auth_service` | **Cero privilegios de tabla**; solo EXECUTE sobre la API de auth (§7). Cierra la forja de `audit.user_id` en la ruta pública |
| `role_platform_console` | SELECT/INSERT/UPDATE en tablas operativas (**sin DELETE** — soft delete); SELECT-only en identidad; **SELECT por columnas** que oculta `secret_hash`, `secret_encrypted` y la clave de refresh; sujeto a RLS |
| `role_bg_worker` | Solo EXECUTE de las purgas GC |

- `EXECUTE` revocado de PUBLIC en todos los schemas (+ default privileges), y
  las tablas nuevas de `auth` no reciben grants por defecto (fail-closed).
- **RLS** habilitado en las tablas multi-tenant (`customers`,
  `customer_billing_profiles`, `customer_apps`, `customer_users`,
  `app_customer_users`, `roles`): política `platform_full_*` para la consola +
  `tenant_scope_*` que filtra por el GUC `app.current_customer_id` (preparada
  para futuros roles customer-scoped). El owner y los SECURITY DEFINER
  bypassean RLS.
- `fn_enforce_user_protection`: sin actor (`audit.user_id` NULL) = **DENY**
  sobre usuarios protegidos — contexto ausente no solo deja auditoría coja,
  rompe operaciones.

---

## 11. Aprovisionamiento de usuarios

Modelo: a cada cliente se le configura un **usuario administrador** en el
onboarding (staff plataforma, vía `admin_ws`), y ese admin invita al resto.

1. **Onboarding de cliente**: `core.customers` → `core.customer_apps` (apps
   contratadas + config + clave de firma) → usuario admin con membresía,
   tripleta y rol admin.
2. **Invitación por email** (nunca contraseñas manuales): si el email no
   existe → `auth.users` **sin credencial** + membresía + tripleta + token
   `invitation` (72 h, reenviable). El invitado fija contraseña
   (`sp_consume_invitation_token` — de paso sella `email_verified_at`) y
   enrola TOTP en su primer acceso (enroll → confirm).
3. **Email ya existente** (multipertenencia): NO se crea identidad — solo
   membresía + tripleta + notificación. El admin de un cliente no edita datos
   personales de usuarios de otros clientes.
4. **Revocar acceso** = soft-delete de membresía/tripleta + revocar sus
   sesiones de ese cliente (`sp_revoke_access_sessions`). **Nunca** tocar
   `auth.users`: la persona puede seguir activa en otras empresas.

---

## 12. Reglas de negocio consolidadas

1. Identidad global única; multipertenencia a clientes; sin slug de cliente
   (todo por UUID).
2. Acceso = 4 niveles activos y vigentes (regla de oro). La BD la aplica en
   `sp_open_session`, `sp_refresh_session` (revalida en cada rotación) y
   `fn_get_effective_permissions`.
3. Login por pasos con ticket efímero de un solo canje; `identifier` acepta
   username o email; 2FA solo TOTP al lanzamiento.
4. `must_change_secret` (o credencial caducada) corta el flujo: no hay
   empresas ni 2FA hasta cambiar la contraseña.
5. `max_sessions` alcanzado → se revoca la sesión más antigua, nunca se
   rechaza el login.
6. Cambio de empresa (switch) sin contraseña ni 2FA: revoca la sesión actual y
   emite una nueva (las claves de firma son por par cliente-app — siempre
   sesión nueva). Una empresa activa por dispositivo y por app.
7. Re-autenticación solo cuando el refresh vence o la sesión es revocada.
8. Reuso de un refresh ya rotado = robo → revocar la cadena completa.
9. Cambiar/resetear contraseña revoca todas las sesiones del usuario.
10. Respuestas opacas por **uniformidad** (mismo código+estatus+cuerpo), no por
    esconder el estatus; los códigos que filtran estado de cuenta jamás se
    conectan al login.
11. Una cookie de refresh **por app** (`auth_refresh__<appCode>`): sesiones de
    apps distintas no se pisan en el mismo navegador; el `appCode` del cliente
    solo selecciona la cookie, nunca decide la sesión.
12. Los permisos efectivos viajan en la respuesta de sesión; el enforcement
    vive en el servidor (resource server + `fn_has_permission`); el front los
    usa solo para UI.
13. Un resource server valida el access token **localmente** (JWKS) y debe
    exigir que el token sea de **su** app (p. ej. `admin_ws` compara el
    `appCode` de la clave JWKS con el suyo).
14. Soft delete universal por `status`; hard-delete de usuarios y credenciales
    bloqueado a no-staff; usuarios protegidos intocables sin actor staff.

---

## 13. Configuración (env) y operación

### 13.1 Variables (validadas al boot — el proceso no arranca si falta algo)

| Variable | Uso |
|---|---|
| `DATABASE_URL` | Conexión como `role_auth_service` |
| `PLATFORM_MASTER_KEY` | AES-256-GCM (32 bytes base64) — se valida el largo al boot |
| `PLATFORM_TICKET_KEY` | Firma de tickets (≥32 chars) |
| `PORT` / `HOST` | Default 3001 / 0.0.0.0 |
| `COOKIE_DOMAIN`, `COOKIE_SECURE`, `COOKIE_SAMESITE` | Cookie de refresh (`strict` default; `none` solo para SPA en otro origen) |
| `CORS_ORIGINS` | Lista blanca separada por comas (vacío = sin CORS) |
| `AUTH_APP_BASE_URL` | Base de los enlaces de email (reset/invitación) |
| `MAIL_TRANSPORT` (`console`/`smtp`/`memory`) + `MAIL_FROM`, `SMTP_*` | Correo transaccional (fail-fast si smtp incompleto; `memory` = outbox de tests) |
| `OTP_SENDER_TRANSPORT` (`console`/`twilio`/`memory`) + `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_SMS_FROM`, `TWILIO_WHATSAPP_FROM` | Envío del OTP 2FA por SMS/WhatsApp (fail-fast si twilio incompleto) |
| `RATE_LIMIT_DISABLED` | Solo tests/desarrollo |
| `LOG_LEVEL` | pino |

En `NODE_ENV=production` aborta el arranque si: `COOKIE_SECURE=false`,
`CORS_ORIGINS` vacío o con `*`, o llaves con valores placeholder.

### 13.2 Bootstrap de datos

1. `db/init.sql` (o los scripts 00..08 + 99 en orden, como `role_owner`):
   esquema completo + seed — usuarios `system` (protegido, sin credencial) y
   `admin` (sin credencial aún), app `admin-app`, catálogo de 26 permisos de
   consola, clientes `platform`/`base`/`demo` con membresías, tripletas y rol
   `superadmin`.
2. `pnpm seed:login` (auth_ws): la criptografía que SQL no puede generar — el
   hash argon2id del admin y una clave Ed25519 **por par cliente-app**
   (cifrada con `PLATFORM_MASTER_KEY`). Hasta entonces el admin no puede
   loguear.

### 13.3 Mantenimiento programado

| Tarea | Mecanismo |
|---|---|
| Purga de sesiones caducadas | `auth.sp_purge_expired_sessions(grace)` → `status='deleted'` (rol `role_bg_worker`) |
| Purga de tokens de verificación | `auth.sp_purge_expired_verification_tokens(grace)` (consumidos se conservan) |
| Retención del event log | DROP manual de particiones mensuales (`audit.event_log_YYYY_MM`) por el DBA |
| Particiones nuevas | Auto-creadas por el propio trigger de auditoría |

### 13.4 Testing

Suite de integración (`test/auth_flow.test.ts`, vitest + `app.inject`) contra
un Postgres real de prueba (puerto 5433, sembrado con `init.sql` +
`seed:login` y las llaves de prueba de `test/setup.ts`). Cubre el flujo
completo (login → sesión → verify → refresh → switch → logout), opacidad,
i18n, JWKS y el aislamiento de cookies por app.

---

## 14. Consumidores conocidos

| Consumidor | Integración |
|---|---|
| `admin_app` (SPA consola) | `HttpAuthGateway` — `APP_CODE='admin-app'` en login/refresh/switch/logout; access token en memoria; restore por cookie al arrancar |
| `admin_ws` (API consola) | Resource server: valida el access **localmente** (JWKS cacheado, exige `appCode` propio en la clave) y autoriza con `fn_has_permission`. No emite tokens |
| `residguard_app` | `SessionRepositoryHttp` — `AUTH_APP_CODE='residguard-app'` en login/refresh/logout (sin switch) |
| `auth_app` | Front de flujos de cuenta (reset de contraseña, invitación + enrolamiento 2FA) |
| `base_project` (ERP) | Espeja el contrato en `auth.gateway.ts` (gateway simulado hoy); su catálogo de permisos está pendiente |

Cualquier cambio al contrato de §8.4 debe reflejarse en §2.2 del CLAUDE.md
raíz, en el CLAUDE.md de este servicio y en los gateways de los frontends.
