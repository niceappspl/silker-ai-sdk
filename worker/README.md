# Silker Cloudflare Worker

Runtime security na brzegu Cloudflare - **dowolny backend**, zero zmian w kodzie aplikacji.
Reużywa ten sam silnik detekcji co SDK (`@silker-ai/core`).

## Jak to działa

```
Request → Cloudflare (edge) → Worker Silkera
   ├─ czysto → forward do originu + log do /api/ingest
   └─ atak   → 403 + log do /api/ingest
```

Decyzja block/allow zapada lokalnie na brzegu. Do platformy leci tylko telemetria
(asynchronicznie przez `ctx.waitUntil`) - **zero dodanej latencji od naszych serwerów**.

## Wdrożenie

```bash
npm install
wrangler secret put SILKER_API_KEY      # twój klucz sk_...
```

W `wrangler.toml` ustaw:
- `SILKER_APP_ID` - ID aplikacji z dashboardu Silker,
- `SILKER_TARGET` - origin (np. `https://origin.twoja-domena.com`),
- `routes` - przypięcie do Twojej domeny.

```bash
npm run dev      # lokalny test (wrangler dev)
npm run deploy   # wdrożenie na Cloudflare
```

## Wymagania

- Domena na Cloudflare (Worker działa na Twojej zonie).
- Node 18+ do dev tooling.

## Ograniczenia MVP

- Rate-limit i bany IP działają **per-isolate** (każdy edge liczy osobno).
  Globalny stan (KV / Durable Objects) to kolejny etap (parytet z SDK).
- Inspekcja odpowiedzi (data leak w response) - planowana.
