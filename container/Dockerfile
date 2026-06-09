# Build stage: bundle server + @silker-ai/core into a single file.
# Build context MUST be the repo root (so src/core is available):
#   docker build -f container/Dockerfile -t silker-proxy .
FROM node:20-slim AS build
WORKDIR /build

COPY container/package.json container/package-lock.json* ./container/
COPY container/tsconfig.json ./container/
COPY container/src ./container/src
COPY src ./src

WORKDIR /build/container
RUN npm install --no-audit --no-fund
RUN npm run build

# Runtime stage: minimal, non-root image.
FROM node:20-slim AS runtime
WORKDIR /app

COPY --from=build /build/container/dist/server.js ./server.js

ENV NODE_ENV=production
ENV SILKER_PORT=8080
EXPOSE 8080

# Drop privileges — the bundled server has no write needs.
USER node

# Container-level health probe (served by the proxy, not forwarded to origin).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.SILKER_PORT||8080)+'/_silker/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
