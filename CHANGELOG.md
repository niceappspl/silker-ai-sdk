# Changelog

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
