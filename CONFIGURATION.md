# Silker Agent - Configuration Guide

Complete configuration reference for `@silker-ai/agent` v1.0.2+

---

## Table of Contents

- [Quick Start](#quick-start)
- [Main Options](#main-options)
- [Security Features Detail](#security-features-detail)
  - [Core Security](#core-security)
  - [OWASP Top 10](#owasp-top-10)
  - [Advanced Security](#advanced-security)
  - [Monitoring](#monitoring)
- [Complete Examples](#complete-examples)
- [Environment Setup](#environment-setup)

---

## Quick Start

### Minimal Configuration

```typescript
import { middleware } from '@silker-ai/agent';

// Zero-config: apiKey is read from process.env.SILKER_API_KEY
app.use(middleware());
```

**This is all you need to get started.** Core detectors (SQLi, XSS, path traversal,
prompt injection, rate limiting, data leakage, file upload) are enabled by default.
Advanced detectors are opt-in — see the defaults below.

---

## Main Options

All options are optional. `apiKey`, `appId` and `endpoint` fall back to the
`SILKER_API_KEY`, `SILKER_APP_ID` and `SILKER_ENDPOINT` environment variables.
Without a resolvable `apiKey`, the SDK runs in detection-only mode (no telemetry).

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiKey` | `string` | `process.env.SILKER_API_KEY` | Silker API key for telemetry authentication |
| `appId` | `string` | `process.env.SILKER_APP_ID` | Optional — the platform resolves the app from the API key |
| `endpoint` | `string` | `process.env.SILKER_ENDPOINT`, then auto | API endpoint URL (Auto: `http://localhost:3000` dev, `https://platform.silkerai.com` prod) |
| `debug` | `boolean` | `false` | Enable detailed console logging for debugging |
| `maxPayloadSize` | `number` | `102400` | Maximum payload size to scan in bytes (100KB default, shared by the Express hook, the Edge core and `isAnomaly`) |
| `blockOutgoing` | `boolean` | `false` | Block anomalous OUTGOING `fetch()` calls (default: monitor-only, telemetry without blocking) |
| `trustProxy` | `boolean` | `true` | Trust proxy headers (`x-forwarded-for`, `x-real-ip`) for client IP resolution. **Set to `false` if your app is NOT behind a trusted proxy** — otherwise XFF is client-spoofable and IP-keyed bans / rate limits are unreliable. With `false`, the socket remote address is used |
| `store` | `SilkerStateStore` | in-memory | Optional shared state store (e.g. Redis) for distributing rate-limit counters and IP bans across instances. See [Distributed state store](#distributed-state-store-redis) |
| `threatIntel` | `{ ips?, domains? }` | — | Extra threat-intelligence IPs/domains merged with the (small) builtin baseline lists |
| `features` | `object` | See below | Feature toggles object to enable/disable specific checks |

---

## Security Features Detail

Core detectors are **enabled by default** (`true`). Advanced detectors that tend to
produce false positives on normal production traffic are **opt-in** (`false`) —
set them to `true` explicitly to enable. An explicit value always wins over the default.

### Core Security

Essential protection against common web attacks.

| Feature | Key | Description | Default |
|---------|-----|-------------|---------|
| **Rate Limiting** | `rateLimit` | Protects against brute-force and DoS attacks by limiting requests (60 req/min per IP). Uses sliding window algorithm. | `true` |
| **SQL Injection** | `sqliDetection` | Detects and blocks SQL injection patterns in query parameters, body, and headers using heuristic analysis. | `true` |
| **XSS Protection** | `xssDetection` | Prevents Cross-Site Scripting (XSS) attacks by detecting malicious scripts in input data. | `true` |
| **Path Traversal** | `pathTraversalDetection` | Blocks attempts to access unauthorized files via directory traversal (e.g., `../etc/passwd`). | `true` |
| **Prompt Injection** | `promptInjectionDetection` | **AI/LLM Specific:** Detects attempts to manipulate LLM behavior via malicious prompts (jailbreaks, context leaks). | `true` |
| **IP Banning** | `ipBanning` | Automatically bans IP addresses for a period after detecting a security threat or rate limit violation. | `true` |

### OWASP Top 10

Comprehensive coverage of the OWASP Top 10 web application security risks.
Most of these are opt-in because they flag legitimate traffic on many production APIs.

| Feature | Key | Description | Default |
|---------|-----|-------------|---------|
| **Broken Access Control** | `accessControlDetection` | Detects privilege escalation attempts and unauthorized resource access. | `false` (opt-in) |
| **Cryptographic Failures** | `cryptographicValidation` | Checks for weak encryption usage and exposure of sensitive data in transit. | `false` (opt-in) |
| **Vulnerable Components** | `vulnerableComponentsDetection` | Identifies usage of known vulnerable dependencies or components. | `false` (opt-in) |
| **Auth Failures** | `authenticationValidation` | Detects weak authentication mechanisms and brute-force attempts. | `false` (opt-in) |
| **Integrity Failures** | `softwareIntegrityValidation` | Verifies integrity of software updates and critical data flows. | `false` (opt-in) |
| **Logging Failures** | `auditLogging` | Ensures critical security events are logged for audit trails. | `true` |
| **SSRF (incoming)** | `ssrfDetection` | Server-Side Request Forgery detection for INCOMING requests (flags requests whose URL targets internal addresses). Opt-in — noisy on many APIs. | `false` (opt-in) |
| **SSRF (outgoing)** | `outboundSsrfProtection` | SSRF protection for OUTGOING `fetch()` calls (internal addresses, cloud metadata endpoints) — the primary purpose of the fetch hook, hence default ON. Backward compat: an explicit `ssrfDetection: false` also disables outbound. | `true` |
| **Injection** | *Covered by `sqliDetection`* | (See Core Security) | `true` |

### Advanced Security

Specialized protection for modern applications and APIs.

| Feature | Key | Description | Default |
|---------|-----|-------------|---------|
| **CSRF** | `csrfDetection` | Cross-Site Request Forgery protection. Verifies Origin/Referer headers for state-changing requests. | `false` (opt-in) |
| **IDOR** | `idorDetection` | Insecure Direct Object Reference detection. Checks for unauthorized access to objects via IDs. | `false` (opt-in) |
| **Host Header Injection** | `hostHeaderInjectionDetection` | Prevents attacks that manipulate the Host header to poison caches or reset passwords. | `false` (opt-in) |
| **Data Leakage** | `dataLeakageDetection` | Scans payloads for sensitive data (API keys, Credit Cards, SSN, PII). Set to `false` to disable, or pass `{ strategy: 'block' \| 'redact' \| 'monitor' }`. | `true` |
| **Session Anomalies** | `sessionAnomaliesDetection` | Behavioral analysis to detect session hijacking and unusual user patterns. | `false` (opt-in) |
| **File Upload** | `fileUploadDetection` | Scans uploaded files for malware and validates file types/extensions. | `true` |
| **Third Party** | `thirdPartyDetection` | Monitors and validates interactions with third-party APIs and services. | `false` (opt-in) |
| **Compliance** | `complianceDetection` | Checks for violations of GDPR, HIPAA, and other regulatory requirements. | `false` (opt-in) |
| **Threat Intel** | `threatIntelligence` | Checks IPs/domains/user-agents against a **baseline builtin list** (a handful of seed entries + known scanner user-agents). This is a heuristic baseline, not a live feed — extend it with your own lists via the top-level `threatIntel: { ips, domains }` option. | `false` (opt-in) |
| **Zero Trust** | `zeroTrustDetection` | Enforces strict verification for every request (auth headers, origin, confirmation tokens for destructive ops). Heuristic baseline. The business-hours check is **off by default** (nonsense for global APIs) — enable explicitly via `performZeroTrustCheck(event, { businessHoursCheck: true })`. | `false` (opt-in) |

### Monitoring

| Feature | Key | Description | Default |
|---------|-----|-------------|---------|
| **Cloud Communication** | `cloudCommunication` | Sends sanitized security events to Silker Cloud for analysis and dashboard reporting. | `true` |

---

## Distributed state store (Redis)

By default, rate-limit counters and IP bans are kept in process memory.
For multi-instance deployments, pass a `store` implementing `SilkerStateStore`
to share that state (e.g. via Redis):

```typescript
import { createClient } from 'redis';
import { middleware, SilkerStateStore } from '@silker-ai/agent';

const redis = createClient({ url: process.env.REDIS_URL });
await redis.connect();

const redisStore: SilkerStateStore = {
  async incr(key, windowMs) {
    const count = await redis.incr(key);
    if (count === 1) await redis.pExpire(key, windowMs);
    return count;
  },
  async get(key) {
    return redis.get(key);
  },
  async set(key, value, ttlMs) {
    await redis.set(key, value, ttlMs ? { PX: ttlMs } : undefined);
  },
  async delete(key) {
    await redis.del(key);
  },
};

app.use(middleware({ store: redisStore }));
```

**Consistency tradeoff:** `isAnomaly` is synchronous, so the external store is
never awaited on the request path. The local in-memory state stays
authoritative for the block/allow decision; increments and bans are mirrored
to the external store fire-and-forget, and shared counters/bans are pulled
back best-effort. State across instances is therefore **eventually
consistent** — a single instance may briefly let traffic through above the
shared limit before the shared counter propagates.

---

## Complete Examples

### 1. Full Configuration (Explicit)

```typescript
import express from 'express';
import { middleware } from '@silker-ai/agent';

const app = express();

app.use(middleware({
  // Main Options (all optional — env fallback: SILKER_API_KEY / SILKER_APP_ID / SILKER_ENDPOINT)
  apiKey: process.env.SILKER_API_KEY!,
  appId: 'd6bd4319-5aa9-49c8-b760-b4dfce661cbc',
  endpoint: 'https://platform.silkerai.com',
  debug: false,
  maxPayloadSize: 1048576, // 1MB

  // Feature Toggles (explicit values win over defaults)
  features: {
    // Core (default: true)
    rateLimit: true,
    sqliDetection: true,
    xssDetection: true,
    pathTraversalDetection: true,
    promptInjectionDetection: true,
    dataLeakageDetection: true,
    fileUploadDetection: true,
    ipBanning: true,
    auditLogging: true,
    cloudCommunication: true,

    // Advanced detectors (default: false — opt-in)
    accessControlDetection: true,
    cryptographicValidation: true,
    vulnerableComponentsDetection: true,
    authenticationValidation: true,
    softwareIntegrityValidation: true,
    ssrfDetection: true,
    csrfDetection: true,
    idorDetection: true,
    hostHeaderInjectionDetection: true,
    sessionAnomaliesDetection: true,
    thirdPartyDetection: true,
    complianceDetection: true,
    threatIntelligence: true,
    zeroTrustDetection: true
  }
}));

app.listen(3000);
```

### 2. Development Mode

Optimized for local development with verbose logging.

```typescript
app.use(middleware({
  apiKey: process.env.SILKER_API_KEY!,
  endpoint: 'http://localhost:3000', // Local backend
  debug: true                        // Verbose logging
}));
```

### 3. Production Mode

Optimized for security and performance.

```typescript
app.use(middleware({
  apiKey: process.env.SILKER_API_KEY!,
  endpoint: 'https://platform.silkerai.com',
  debug: false,
  maxPayloadSize: 102400, // 100KB
  // Core detectors enabled by default; advanced detectors are opt-in
}));
```

### 4. Selective Protection (API Gateway)

Enabling only specific checks for a gateway service.

```typescript
app.use(middleware({
  apiKey: process.env.SILKER_API_KEY!,
  features: {
    // Enable only these
    rateLimit: true,
    sqliDetection: true,
    xssDetection: true,

    // Disable the remaining on-by-default features
    pathTraversalDetection: false,
    promptInjectionDetection: false,
    dataLeakageDetection: false,
    fileUploadDetection: false,
    auditLogging: false,
    cloudCommunication: false
    // Advanced detectors are already off by default
  }
}));
```

---

## Environment Setup

### Required Environment Variables

```bash
# .env file
SILKER_API_KEY=sk_your_api_key_here
```

### Environment Variables

```bash
# API Key (required for telemetry) — get from platform.silkerai.com
SILKER_API_KEY=sk_your_api_key_here

# Optional — the platform resolves the app from the API key
SILKER_APP_ID=your-app-id

# Optional — override the telemetry endpoint
SILKER_ENDPOINT=https://platform.silkerai.com

# Environment (auto-detected)
NODE_ENV=production
```

---

## TypeScript Support

Full TypeScript support with auto-completion:

```typescript
import { SilkerOptions, SilkerFeatures } from '@silker-ai/agent';

const config: SilkerOptions = {
  apiKey: process.env.SILKER_API_KEY!,
  appId: 'my-app',
  debug: true,
  features: {
    rateLimit: true,
    sqliDetection: true,
    // ... TypeScript will autocomplete all available features
  }
};

app.use(middleware(config));
```

---

## Performance Considerations

### maxPayloadSize

- **Default**: 102400 bytes (100KB) — one shared limit across the Express hook, the Edge core and `isAnomaly`
- **Impact**: Larger payloads = slower scanning (regex/heuristics are CPU-bound)
- **Best Practice**: keep the default unless attacks hide deeper in very large bodies

```typescript
maxPayloadSize: 102400   // Fast   - 100KB (default)
maxPayloadSize: 1048576  // Medium - 1MB
maxPayloadSize: 5242880  // Slow   - 5MB
```

### Feature Impact

| Feature | Performance Impact |
|---------|-------------------|
| `rateLimit` | Very Low |
| `sqliDetection` | Low |
| `xssDetection` | Low |
| `pathTraversalDetection` | Very Low |
| `promptInjectionDetection` | Low |
| `ipBanning` | Very Low |
| `threatIntelligence` | Medium (network call) |
| `sessionAnomaliesDetection` | Medium (stateful) |
| All others | Low |

---

## Migration from v1.0.1

If upgrading from v1.0.1, remove these deprecated options:

```diff
app.use(middleware({
  apiKey: process.env.SILKER_API_KEY!,
  appId: 'xxx',
  endpoint: 'https://platform.silkerai.com',
  debug: true,
  maxPayloadSize: 1048576,
- dashboardUrl: 'https://dash.silkerai.com',  // ❌ REMOVED - use endpoint
- proxyMode: false,                        // ❌ REMOVED - not supported
- tokenId: 'user-session-id',             // ❌ REMOVED - not implemented
- failOpen: true,                          // ❌ REMOVED - not implemented
- logger: console,                         // ❌ REMOVED - use debug flag
  features: { ... }
}));
```

---

## Support

- **Documentation**: [https://docs.silkerai.com](https://docs.silkerai.com)
- **API Reference**: [https://silkerai.com/docs](https://silkerai.com/docs)
- **GitHub**: [https://github.com/silker/agent](https://github.com/silker/agent)
- **Issues**: [https://github.com/silker/agent/issues](https://github.com/silker/agent/issues)

---

## License

UNLICENSED - Proprietary Software

Copyright © 2024 Silker AI. All rights reserved.
