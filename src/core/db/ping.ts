import { pool } from "./pool";

/**
 * Comprobación de vida de la BD para el endpoint de health. Es la ÚNICA
 * excepción a "todo SQL pasa por withTransaction" (CLAUDE.md §4): no es una
 * operación de negocio, no toca tablas ni necesita contexto de auditoría —
 * solo confirma que el pool puede tomar una conexión y responder. El pool
 * sigue siendo privado del módulo (no se exporta).
 */
export async function pingDatabase(): Promise<boolean> {
  const client = await pool.connect();
  try {
    await client.query("SELECT 1");
    return true;
  } finally {
    client.release();
  }
}
