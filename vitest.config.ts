import { defineConfig } from "vitest/config";

// Suite de integración (Fase 6.4): construye la app Fastify en proceso y usa
// app.inject() contra un Postgres real ya sembrado (ver test/setup.ts). Toca BD,
// así que los timeouts son holgados. No se paraleliza entre archivos: los tests
// comparten un estado de sesión secuencial (login → sesión → refresh → switch).
export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    setupFiles: ["test/setup.ts"],
    testTimeout: 30_000,
    hookTimeout: 30_000,
    fileParallelism: false,
    pool: "forks",
  },
});
