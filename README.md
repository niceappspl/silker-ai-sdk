# @silker-ai/agent

**Runtime security for AI-powered web apps.**  
Detects and blocks attacks in real-time — SQLi, XSS, prompt injection, SSRF, IDOR, and more.  
Zero code changes to your business logic. Telemetry flows to your [Silker AI dashboard](https://platform.silkerai.com).

[![npm](https://img.shields.io/npm/v/@silker-ai/agent)](https://www.npmjs.com/package/@silker-ai/agent)

---

## Get started in 2 minutes

### Step 1 — Create an account and get your API key

1. Go to [platform.silkerai.com](https://platform.silkerai.com) and sign up (free)
2. Click **New Application** → give it a name (e.g. "my-saas-app")
3. Open **Configuration** → copy your API key: `sk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

> Your API key is unique to each application. Keep it secret — treat it like a password.

---

### Step 2 — Install

```bash
npm install @silker-ai/agent
```

---

### Step 3 — Add your API key to environment variables

Create or edit `.env.local` (Next.js) or `.env` (Express/Node):

```bash
# .env.local
SILKER_API_KEY=sk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

> **Never put the API key directly in your code.** Always use environment variables.  
> On Vercel: Settings → Environment Variables → add `SILKER_API_KEY`.  
> On other platforms: set it wherever you manage your app's env vars.

---

### Step 4 — Initialize Silker

#### Express (zero-config)

```typescript
import express from 'express';
import { middleware } from '@silker-ai/agent';

const app = express();
app.use(express.json());
app.use(middleware()); // reads SILKER_API_KEY from process.env
```

That's it. With `SILKER_API_KEY` set, telemetry flows to your dashboard.
Without a key, the SDK logs a single warning and runs in detection-only mode
(attacks are still blocked, no telemetry) — it never crashes your app.

You can also configure explicitly:

```typescript
app.use(middleware({ apiKey: process.env.SILKER_API_KEY }));
```

---

#### Generic Node.js / Serverless

```typescript
import { initSilker } from '@silker-ai/agent';

await initSilker(); // reads SILKER_API_KEY from process.env

// All outgoing fetch() calls are now monitored
```

---

#### Next.js

The exported `middleware` is an Express-style handler (`(req, res, next)`) and
**does not work in Next.js `middleware.ts`** (Edge runtime uses a different API).

To use Silker with Next.js, run it behind a [custom Express server](https://nextjs.org/docs/pages/guides/custom-server):

```typescript
// server.ts
import express from 'express';
import next from 'next';
import { middleware } from '@silker-ai/agent';

const app = next({ dev: process.env.NODE_ENV !== 'production' });
const handle = app.getRequestHandler();

app.prepare().then(() => {
  const server = express();
  server.use(express.json());
  server.use(middleware()); // reads SILKER_API_KEY from process.env
  server.all('*', (req, res) => handle(req, res));
  server.listen(3000);
});
```

---

### Step 5 — Verify it works

1. Deploy your app (or run locally)
2. Make a request to your API (e.g. `curl http://localhost:3000/api/test`)
3. Open your [Silker AI dashboard](https://platform.silkerai.com/apps) → your app → **Dashboard**
4. You should see the request appear within seconds

If the status badge shows **Live** (green) — you're protected. ✓

---

## CLI setup wizard (optional)

If you prefer guided setup:

```bash
npx @silker-ai/agent init
```

The wizard:
- Detects your framework (Next.js, Express, Node.js)
- Asks for your API key and saves it to `.env.local`
- Shows the exact code snippet to add
- Installs the package if not already installed

---

## What gets protected

**On by default** (low false-positive rate, safe for production APIs):

| Attack | Detected | Blocked |
|---|---|---|
| SQL Injection | ✓ | ✓ |
| XSS (Cross-Site Scripting) | ✓ | ✓ |
| Path Traversal | ✓ | ✓ |
| Prompt Injection (LLM) | ✓ | ✓ |
| Rate Limiting / Brute Force | ✓ | ✓ |
| Data Leakage (PII, API keys) | ✓ | redact/block |
| Malicious File Upload | ✓ | ✓ |
| SSRF (outgoing `fetch` calls) | ✓ | opt-in (`blockOutgoing`) |

**Opt-in** (these tend to flag normal traffic on production APIs, so they're
disabled unless you explicitly turn them on in `features`):

`csrfDetection`, `ssrfDetection` (incoming), `idorDetection`,
`hostHeaderInjectionDetection`, `accessControlDetection`,
`authenticationValidation`, `cryptographicValidation`,
`vulnerableComponentsDetection`, `softwareIntegrityValidation`,
`sessionAnomaliesDetection`, `thirdPartyDetection`, `complianceDetection`,
`threatIntelligence`, `zeroTrustDetection`

---

## Advanced configuration (optional)

```typescript
import { middleware } from '@silker-ai/agent';

app.use(middleware({
  // apiKey defaults to process.env.SILKER_API_KEY
  debug: true, // logs blocked requests to console

  // Opt into advanced detectors (disabled by default):
  features: {
    csrfDetection: true,
    idorDetection: true,
    zeroTrustDetection: true,
    // ... see CONFIGURATION.md for the full list and defaults
  }
}));
```

### Outgoing request monitoring (`fetch` hook)

When initialized via `initSilker()`, Silker also monitors outgoing `fetch()`
calls (including SSRF to internal addresses / cloud metadata endpoints).
By default this is **monitor-only**: anomalies are reported to your dashboard
but the request is never blocked. To actively block malicious outgoing
requests, opt in:

```typescript
await initSilker({ blockOutgoing: true });
```

Full list of options: [CONFIGURATION.md](./CONFIGURATION.md)

---

## How it works

```
Your app receives a request
       ↓
Silker inspects it in ~0ms (heuristic, no network call)
       ↓
Clean request → passes through to your handler
Malicious request → blocked (403), event logged
       ↓
Telemetry sent async to platform.silkerai.com/api/ingest
       ↓
Visible in your dashboard: threats, requests, map, AI analysis
```

**Fail-safe:** if the Silker platform is unreachable, your app continues working normally. Security events are dropped (not your traffic).

---

## Compatibility

| Runtime | Status |
|---|---|
| Node.js ≥ 14 | ✅ |
| Express / NestJS | ✅ |
| Next.js (custom Express server) | ✅ |
| Next.js Edge `middleware.ts` | ❌ not supported (Express-style API) |
| Vercel / AWS Lambda | ✅ (optimized flush) |
| Bun / Deno | ⚠️ experimental |

---

## Frequently asked questions

**Do I need to change my business logic?**  
No. Silker wraps your existing request handler. Zero changes to your routes.

**Does it slow down my app?**  
Detection runs in ~0ms (heuristic, in-process). Telemetry is sent asynchronously after the response — it never blocks your users.

**What if my API key is leaked?**  
Immediately regenerate it in the dashboard (Configuration → Regenerate). The old key stops working instantly.

**Can I use multiple API keys for multiple apps?**  
Yes. Create a separate application in the dashboard for each project. Each gets its own key and its own dashboard.

**Is there a free tier?**  
Yes. Create an account at [platform.silkerai.com](https://platform.silkerai.com).

---

## Support

- Docs: [silkerai.com/docs](https://silkerai.com/docs)
- Email: [support@silkerai.com](mailto:support@silkerai.com)
- Dashboard: [platform.silkerai.com](https://platform.silkerai.com)

---

Proprietary Software. © 2026 Silker AI. All rights reserved.
