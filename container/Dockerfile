# Build stage: bundle server + @silker-ai/core do jednego pliku
FROM node:20-slim AS build
WORKDIR /build

# Potrzebny core z repo SDK
COPY container/package.json container/package-lock.json* ./container/
COPY container/tsconfig.json ./container/
COPY container/src ./container/src
COPY src ./src

WORKDIR /build/container
RUN npm install --no-audit --no-fund
RUN npm run build

# Runtime stage: minimalny obraz
FROM node:20-slim AS runtime
WORKDIR /app
COPY --from=build /build/container/dist/server.js ./server.js

ENV SILKER_PORT=8080
EXPOSE 8080
CMD ["node", "server.js"]
