# syntax=docker/dockerfile:1.7
ARG NODE_VERSION=20

# Supply-chain hardening: base images are pinned by digest for reproducible
# builds. To refresh a digest:
#   docker buildx imagetools inspect node:20-slim
#   docker buildx imagetools inspect gcr.io/distroless/nodejs20-debian12:nonroot
# Dependabot keeps these updated.

# 1. Base with pnpm
FROM node:${NODE_VERSION}-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0 AS base
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

# 2. Build
FROM base AS builder
WORKDIR /app
COPY package.json pnpm-lock.yaml .npmrc ./
RUN --mount=type=cache,id=pnpm,target=/pnpm/store,sharing=locked \
    pnpm install --frozen-lockfile --prefer-offline
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN pnpm build

# 3. Runner — distroless: no shell, no apt/dpkg, no setuid binaries.
# Runs as the built-in nonroot user (uid 65532). ENTRYPOINT is already node,
# so CMD only needs the script path.
FROM gcr.io/distroless/nodejs20-debian12:nonroot@sha256:2cd820156cf039c8b54ae2d2a97e424b6729070714de8707a6b79f20d56f6a9a AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=8080
ENV HOSTNAME="0.0.0.0"

COPY --from=builder --chown=65532:65532 /app/.next/standalone ./
COPY --from=builder --chown=65532:65532 /app/.next/static ./.next/static
COPY --from=builder --chown=65532:65532 /app/public ./public

USER 65532:65532
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:8080/').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

CMD ["server.js"]
