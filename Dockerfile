# syntax=docker/dockerfile:1

# ── Etapa 1: build ──────────────────────────────────────────────────────────
# node:20-slim (Debian/glibc): argon2 y pg traen prebuilds nativos fiables;
# alpine (musl) obligaría a compilar desde fuente (sin toolchain en la imagen).
# pnpm vía corepack para igualar el toolchain real del proyecto: pnpm-lock.yaml
# es la fuente de verdad (el package-lock.json quedó obsoleto).
FROM node:20-slim AS build
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
# El store en /pnpm/store: coincide con el cache mount de abajo (build más
# rápido) y, al estar en otro mount que node_modules, pnpm COPIA los paquetes
# a node_modules en vez de hardlinkear → node_modules autocontenido para
# copiarlo tal cual a la imagen final.
ENV PNPM_STORE_DIR=/pnpm/store
RUN corepack enable
WORKDIR /app

# Dependencias con lockfile congelado (build reproducible). El directorio
# vendorizado de structure-verifier viaja en el contexto (vendor/), así que el
# `file:` del package.json resuelve SIN salir del contexto de build de auth_ws/.
COPY package.json pnpm-lock.yaml ./
COPY vendor ./vendor
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm config set store-dir /pnpm/store && pnpm install --frozen-lockfile

COPY tsconfig.json ./
COPY src ./src
RUN pnpm run build

# Recorta a dependencias de producción (fuera devDeps) para copiarlas tal cual.
RUN pnpm prune --prod

# ── Etapa 2: runtime ────────────────────────────────────────────────────────
FROM node:20-slim
# NODE_ENV=production es OBLIGATORIO: sin él, server.ts intenta cargar el
# transporte pino-pretty (devDependency, ausente en prod) y el proceso muere al
# boot; además activa las validaciones fail-fast de producción de config.ts.
ENV NODE_ENV=production
WORKDIR /app

# tini como PID 1: reenvía SIGTERM y cosecha zombies → shutdown limpio.
RUN apt-get update && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/*

# Solo artefactos de runtime: node_modules ya podado (pnpm copió structure-verifier
# a real files en el store, así que es autocontenido) + dist. Sin fuentes, sin
# devDependencies, sin vendor/ (ya no hace falta en runtime).
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./

# El servicio escucha en 0.0.0.0:3001 por defecto (config.ts §9).
EXPOSE 3001
USER node

# Healthcheck de LIVENESS (/health): ¿responde el proceso? Se evita apuntar al
# readiness (/health/ready, que verifica la BD) para no reciclar el contenedor
# ante un blip de Postgres — ese chequeo lo hace la probe del orquestador.
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3001)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "dist/server.js"]
