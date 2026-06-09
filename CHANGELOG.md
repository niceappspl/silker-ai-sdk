# Changelog

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
