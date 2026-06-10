# Silker self-host proxy (container)

Runtime security for **any backend** (PHP, Java, Python, Go, Ruby, .NET, Rails…) on
**any host** - **no Cloudflare, no code changes**. It reuses the exact same detection
engine as the Node SDK and the Cloudflare Worker (`@silker-ai/core`).

Use this when your app is not Node.js, or when you can't (or don't want to) add a
middleware to the codebase.

## How it works

```
Internet → Silker proxy (your container) → your app (origin)
   ├─ clean   → forwarded + async log to /api/ingest
   └─ attack  → 403 + async log to /api/ingest
```

The block/allow decision happens locally inside the container; only sanitized
telemetry leaves to the platform (async, off the response path). A single instance
keeps consistent in-memory state, so rate-limiting and IP bans work out of the box
(no KV/Durable Objects needed as on the edge).

## Quick start (published image)

```bash
docker run -p 8080:8080 \
  -e SILKER_API_KEY=sk_xxx \
  -e SILKER_APP_ID=your-app-id \
  -e SILKER_TARGET=http://your-app:3000 \
  ghcr.io/niceappspl/silker-proxy:latest
```

Then point your traffic at `:8080` instead of your app. That's it - the proxy
inspects every request and forwards clean traffic to `SILKER_TARGET`.

## Build from source

Build context must be the repo root (so `src/core` is bundled in):

```bash
docker build -f container/Dockerfile -t silker-proxy .
docker run -p 8080:8080 \
  -e SILKER_API_KEY=sk_xxx \
  -e SILKER_APP_ID=your-app-id \
  -e SILKER_TARGET=http://your-app:3000 \
  silker-proxy
```

## Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SILKER_API_KEY` | API key (`sk_...`) from your dashboard | – (without it: telemetry off, detection still active) |
| `SILKER_APP_ID` | Application ID from the dashboard | – |
| `SILKER_TARGET` | Origin to forward clean traffic to | `http://localhost:3000` |
| `SILKER_ENDPOINT` | Platform URL | `https://platform.silkerai.com` |
| `SILKER_PORT` | Proxy listen port | `8080` |

Detection features are managed in the **Silker dashboard** and applied automatically -
no flags to set here.

## Health check

The proxy serves `GET /_silker/health` itself (never forwarded to the origin),
returning `{ "status": "ok" }`. The image ships with a Docker `HEALTHCHECK` using it.

## Per-stack examples

The proxy is language-agnostic - in every case you put it in front of your app and
set `SILKER_TARGET` to the app's address. Examples (docker-compose):

### Java / Spring Boot

```yaml
services:
  silker:
    image: ghcr.io/niceappspl/silker-proxy:latest
    ports: ["8080:8080"]
    environment:
      SILKER_API_KEY: sk_xxx
      SILKER_APP_ID: your-app-id
      SILKER_TARGET: http://app:8080   # Spring Boot default
    depends_on: [app]
  app:
    build: .          # your Spring Boot image
    expose: ["8080"]
```

### Python / Django / FastAPI

```yaml
  silker:
    image: ghcr.io/niceappspl/silker-proxy:latest
    ports: ["8080:8080"]
    environment:
      SILKER_API_KEY: sk_xxx
      SILKER_APP_ID: your-app-id
      SILKER_TARGET: http://app:8000   # gunicorn/uvicorn
    depends_on: [app]
```

### PHP / Laravel, Go, Ruby on Rails, .NET

Same shape - only `SILKER_TARGET` changes to your app's port
(`:9000`/`:80` for PHP-FPM/nginx, `:8080` for Go, `:3000` for Rails, `:5000` for .NET).

## Behind an existing reverse proxy (Nginx / Caddy / Traefik)

Point your edge proxy at Silker, and set `SILKER_TARGET` to the real origin:

```
# Caddy
your-domain.com {
  reverse_proxy silker:8080
}
```

```nginx
# Nginx
location / {
  proxy_pass http://silker:8080;
  proxy_set_header X-Real-IP $remote_addr;
}
```

Forward `X-Real-IP` / `X-Forwarded-For` so client IPs (and IP bans) are accurate.

## Local dev (without Docker)

```bash
cd container && npm install
SILKER_API_KEY=sk_xxx SILKER_APP_ID=app SILKER_TARGET=http://localhost:3000 npm run dev
```
