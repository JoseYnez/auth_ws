import { Pool } from "pg";
import { config } from "../../config";

/**
 * Privado de core/db: SOLO with_transaction.ts puede importarlo. El resto
 * del servicio recibe `tx` dentro de withTransaction — nunca el pool
 * (CLAUDE.md §4: sin contexto de auditoría no hay SQL).
 */
export const pool = new Pool({ connectionString: config.databaseUrl });
