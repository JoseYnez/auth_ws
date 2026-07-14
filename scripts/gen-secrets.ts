/**
 * gen-secrets.ts — Genera secretos criptográficos frescos para un .env de
 * producción (Fase 6.1). Imprime, listos para pegar:
 *
 *   PLATFORM_MASTER_KEY  → 32 bytes aleatorios en base64 (clave AES-256-GCM del
 *                          cifrado en reposo de los campos *_encrypted).
 *   PLATFORM_TICKET_KEY  → 48 bytes aleatorios en base64 (≥32 bytes de entropía;
 *                          firma del ticket efímero de login).
 *
 * Ambos con `crypto.randomBytes` (CSPRNG). NO toca la BD ni el entorno: solo
 * imprime. Cada ejecución produce secretos nuevos e irrepetibles.
 *
 * USO:
 *   pnpm gen:secrets
 *
 * Pega la salida en el .env del despliegue (o en el gestor de secretos). Nunca
 * los guardes en el repo. Rotar PLATFORM_MASTER_KEY invalida todo lo cifrado en
 * reposo (claves de firma, secretos TOTP): planifica la rotación.
 */

import { randomBytes } from "node:crypto";

// AES-256-GCM exige exactamente 32 bytes (256 bits). config.ts lo valida al boot.
const masterKey = randomBytes(32).toString("base64");
// El ticket key se estira con sha256 para firmar; con 48 bytes superamos con
// holgura el mínimo de 32 caracteres/entropía que exige config.ts.
const ticketKey = randomBytes(48).toString("base64");

console.log("# Secretos generados con node:crypto (CSPRNG). Pégalos en tu .env de producción.");
console.log("# No los guardes en el repositorio.");
console.log("");
console.log(`PLATFORM_MASTER_KEY=${masterKey}`);
console.log(`PLATFORM_TICKET_KEY=${ticketKey}`);
