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
| `maxPayloadSize` | `number` | `1048576` | Maximum payload size to scan in bytes (1MB default) |
| `blockOutgoing` | `boolean` | `false` | Block anomalous OUTGOING `fetch()` calls (default: monitor-only, telemetry without blocking) |
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
| **SSRF** | `ssrfDetection` | Server-Side Request Forgery prevention for INCOMING requests. Outgoing `fetch()` calls are always checked for SSRF unless this is explicitly `false`. | `false` (opt-in) |
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
| **Threat Intel** | `threatIntelligence` | Checks IPs and signatures against global threat intelligence feeds. | `false` (opt-in) |
| **Zero Trust** | `zeroTrustDetection` | Enforces strict verification for every request, assuming no trust by default. | `false` (opt-in) |

### Monitoring

| Feature | Key | Description | Default |
|---------|-----|-------------|---------|
| **Cloud Communication** | `cloudCommunication` | Sends sanitized security events to Silker Cloud for analysis and dashboard reporting. | `true` |

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

- **Default**: 1048576 bytes (1MB)
- **Recommended**: 1048576 - 5242880 bytes (1-5MB)
- **Impact**: Larger payloads = slower scanning
- **Best Practice**: Set to the maximum expected request size

```typescript
maxPayloadSize: 1048576  // Fast  - 1MB
maxPayloadSize: 5242880  // Medium - 5MB
maxPayloadSize: 10485760 // Slow  - 10MB
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
