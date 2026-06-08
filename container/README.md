# Silker self-host proxy (kontener)

Runtime security dla **dowolnego backendu** (PHP, Java, Python, Go, Ruby, .NET...) i
dowolnego hostingu - **bez Cloudflare**, bez zmian w kodzie aplikacji.
Reużywa ten sam silnik detekcji co SDK i Worker (`@silker-ai/core`).

## Jak to działa

```
Request → Silker proxy (Twój kontener) → Twoja aplikacja (origin)
   ├─ czysto → forward + log do /api/ingest
   └─ atak   → 403 + log do /api/ingest
```

Decyzja zapada lokalnie w kontenerze; do platformy leci tylko telemetria async.
Jedna instancja = spójny stan w pamięci, więc rate-limit i bany IP działają od razu
(bez KV/DO potrzebnych na brzegu).

## Uruchomienie (Docker)

Build z katalogu repo (context = root, żeby dołączyć `src/core`):

```bash
docker build -f container/Dockerfile -t silker-proxy .
docker run -p 8080:8080 \
  -e SILKER_API_KEY=sk_xxx \
  -e SILKER_APP_ID=twoj-app-id \
  -e SILKER_TARGET=http://twoja-app:3000 \
  silker-proxy
```

Albo docker-compose (przykład z originem):

```bash
docker compose -f container/docker-compose.example.yml up --build
```

## Lokalnie (bez Dockera)

```bash
cd container && npm install
SILKER_API_KEY=sk_xxx SILKER_APP_ID=app SILKER_TARGET=http://localhost:3000 npm run dev
```

## Zmienne środowiskowe

| Zmienna | Opis | Domyślnie |
|---------|------|-----------|
| `SILKER_API_KEY` | Klucz API (sk_...) | - (bez niego telemetria off, detekcja działa) |
| `SILKER_APP_ID` | ID aplikacji w dashboardzie | - |
| `SILKER_TARGET` | Origin do forwardu | `http://localhost:3000` |
| `SILKER_ENDPOINT` | URL platformy | `https://platform.silkerai.com` |
| `SILKER_PORT` | Port nasłuchu proxy | `8080` |

## Wpięcie za istniejący reverse proxy (Nginx/Caddy)

Skieruj ruch z Twojego proxy na Silker, a `SILKER_TARGET` ustaw na origin:

```
# Caddy
twoja-domena.com {
  reverse_proxy silker:8080
}
```
