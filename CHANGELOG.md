# Changelog

## [1.3.3] - 2026-06-10
### Fewer prompt-injection false positives on LLM routes
- **New LLM-route blocking policy** — LLM routes previously blocked on ANY prompt-injection detection, flagging benign UX roleplay ("act as a translator", "pretend you are a pirate", "simulate a dice roll", "roleplay as …") at low severity. The policy now blocks on **medium+ severity, or a low-severity match that carries a high-confidence override signal** (`shouldBlockPromptInjectionOnLlmRoute`). Pure persona-roleplay passes; roleplay combined with an override/jailbreak signal still escalates and is blocked. Benchmark LLM-route FPR dropped 24.4% → 0.0% with TPR staying high (98.3% → 94.9%); SQLi/XSS unchanged (100%/0%)
- **Compound scoring via `overrideSignal`** — `detectPromptInjection` now flags whether a high-confidence category (override, jailbreak, extraction, exfiltration, delimiter/system manipulation, encoding, multilingual, obfuscation) matched, vs. standalone persona-roleplay or generic chain phrasing
- **Fixed: `new (instructions|role|mode|system)` over-match** — this no longer fires on benign nouns like "the new instructions for assembling the furniture"; it now requires an injection-context anchor (directive colon `new instructions:`, an activation verb `follow/enter/switch to … new role`, or an assignment `your new role is …`)

## [1.3.2] - 2026-06-10
### Detection correctness, proxy safety & distributed state
- **Fixed: multipart upload false positives** — multipart requests without parsed file metadata (typical Express without multer) are no longer flagged/blocked; only real indicators (dangerous extensions/filenames, malicious magic bytes, path traversal) trigger the file-upload detector. Raw (non-JSON) bodies and validator errors now fail open
- **Unified feature defaults** — single shared `isFeatureEnabled` helper (`DEFAULT_FEATURES`-based) used by both `isAnomaly` and `detectThreatType`; previously `detectThreatType` treated undefined opt-in detectors as enabled
- **Unified payload scan limit** — one shared `DEFAULT_SCAN_LIMIT_BYTES` (100KB) across the Express hook (was 10KB), the Edge core (was 50KB) and `isAnomaly` (was 1MB); `maxPayloadSize` is honored everywhere, including the Express hook and the Next adapter
- **New `outboundSsrfProtection` feature flag** (default **true**) — SSRF checking of outgoing `fetch()` calls is now an explicit, documented feature, separate from incoming `ssrfDetection` (still opt-in). Backward compat: explicit `ssrfDetection: false` also disables outbound. Outbound SSRF threats are now classified as `SSRF` (was generic `Security Anomaly`)
- **New `trustProxy` option** (default true) — set `trustProxy: false` when not behind a proxy so the spoofable `x-forwarded-for` header is ignored and the socket remote address is used for IP-keyed bans/rate limits
- **Fixed: stateful `/g` regexes** — `detectJailbreak` no longer returns intermittent false negatives caused by `lastIndex` leakage on repeated calls
- **Secrets in request bodies now block** — high-confidence secrets (AWS keys, Stripe live keys, GitHub/Google/Slack tokens, client secrets, private keys, DB connection strings) are blocked regardless of HTTP method (was GET-only); password fields on auth endpoints remain allowed and the dataLeakage `block`/`redact`/`monitor` strategy contract is unchanged
- **New pluggable state store** — `SilkerStateStore` interface + `InMemoryStateStore`; pass `store` (e.g. a Redis adapter) to share rate-limit counters and IP bans across instances (best-effort mirroring, eventual consistency; local memory stays authoritative for the sync decision)
- **Fixed: stale client version header** — `x-silker-client-version` now reports the real package version via a generated `src/version.ts` (synced from package.json by a `prebuild` script)
- **Docs/CLI** — README now documents the `@silker-ai/agent/next` Edge adapter, `trustProxy` and `store`; `npx silker init` emits a correct `middleware.ts` snippet for Next.js
- **Edge adapter applies remote config** — `nextMiddleware` now applies dashboard-managed `features` and banned IPs from the ingest response (parity with the node telemetry path); respects `remoteConfig: false`
- **Threat intel lists extensible** via `threatIntel: { ips, domains }` (merged with builtin baseline); zero-trust business-hours check is now opt-in (default off)
- Added GitHub Actions CI (tests + build on PRs and pushes to master/main)

## [1.3.0] - 2026-06-09
### Next.js Edge adapter & deeper LLM/AI threat detection
- New `@silker-ai/agent/next` subpath export: `nextMiddleware(options?)` returns an App Router / Edge-runtime compatible `(request) => Promise<Response>` handler built on the edge-safe core (parity with the Cloudflare Worker, fail-open, fire-and-forget telemetry). `next` is an optional peer dependency — the SDK builds and tests without it
- Expanded LLM/AI prompt-injection detection with classified subtypes via `classifyPromptInjection`: `jailbreak` (high), `system_prompt_extraction` (high), `instruction_override` (high), `data_exfiltration_via_llm` (critical); threats keep `type: "Prompt Injection"` and carry the subtype in the description for the dashboard "AI Security" breakdown
- Broader LLM route coverage: `/v1/responses`, `/api/agent`, `/api/copilot`, `/api/assistant`, `/messages`

## [1.2.0] - 2026-06-09
### Dashboard-managed detection config
- The dashboard is now the source of truth for detection features: toggling protection in the Silker panel updates the running SDK on the next telemetry sync (~5s), no redeploy needed
- Config is delivered over the existing ingest response (no extra requests); opt out with `remoteConfig: false` to keep config in code/env only

## [1.1.0] - 2026-06-09
### Zero-config init & safer defaults
- `middleware()` works with no arguments: `SILKER_API_KEY`, `SILKER_APP_ID` and `SILKER_ENDPOINT` are resolved from env
- Telemetry no longer requires `appId` (platform resolves the app from the API key)
- Safer defaults: high-false-positive detectors (CSRF, zero trust, access control, SSRF-incoming, IDOR, compliance, threat intel and others) are now opt-in; core protections (SQLi, XSS, path traversal, prompt injection, rate limit, data leakage, file upload) stay on
- Outgoing `fetch` hook is monitor-only by default; blocking requires `blockOutgoing: true`
- Fixed: `dataLeakageDetection: false` now actually disables blocking
- Fixed: per-request context moved to `AsyncLocalStorage` (no more cross-request IP mix-ups under load)
- Removed legacy `/api/dashboard/sync` call (banned IPs sync via ingest response)
- Removed unused `http-proxy` dependency

## [1.0.0] - 2026-06-09
### Initial public release
- Runtime middleware for Next.js, Express, Node.js
- OWASP Top 10 detection (SQLi, XSS, SSRF, prompt injection, and more)
- Real-time telemetry to Silker AI platform
- Cloudflare Worker deployment option
- Docker proxy container option
- 26 test suites
