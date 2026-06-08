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

app.use(middleware({
  apiKey: process.env.SILKER_API_KEY!,
  appId: 'your-app-id'
}));
```

**This is all you need to get started.** All 25 security features are enabled by default.

---

## Main Options

### Required

| Option | Type | Description |
|--------|------|-------------|
| `apiKey` | `string` | **REQUIRED** - Your Silker API key for authentication |

### Optional

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `appId` | `string` | `undefined` | Application ID for dashboard grouping |
| `endpoint` | `string` | Auto | API endpoint URL (Auto: `http://localhost:3000` dev, `https://api.silkerai.com` prod) |
| `debug` | `boolean` | `false` | Enable detailed console logging for debugging |
| `maxPayloadSize` | `number` | `1048576` | Maximum payload size to scan in bytes (1MB default) |
| `features` | `object` | All true | Feature toggles object to disable specific checks |

---

## Security Features Detail

All features are **enabled by default** (`true`). To disable a feature, set it to `false` in the configuration object.

### Core Security

Essential protection against common web attacks.

| Feature | Key | Description | Default |
|---------|-----|-------------|---------|
| **Rate Limiting** | `rateLimit` | Protects against brute-force and DoS attacks by limiting requests (5 req/min per IP). Uses sliding window algorithm. | `true` |
| **SQL Injection** | `sqliDetection` | Detects and blocks SQL injection patterns in query parameters, body, and headers using heuristic analysis. | `true` |
| **XSS Protection** | `xssDetection` | Prevents Cross-Site Scripting (XSS) attacks by detecting malicious scripts in input data. | `true` |
| **Path Traversal** | `pathTraversalDetection` | Blocks attempts to access unauthorized files via directory traversal (e.g., `../etc/passwd`). | `true` |
| **Prompt Injection** | `promptInjectionDetection` | **AI/LLM Specific:** Detects attempts to manipulate LLM behavior via malicious prompts (jailbreaks, context leaks). | `true` |
| **IP Banning** | `ipBanning` | Automatically bans IP addresses for a period after detecting a security threat or rate limit violation. | `true` |

### OWASP Top 10

Comprehensive coverage of the OWASP Top 10 web application security risks.

| Feature | Key | Description | Default |
|---------|-----|-------------|---------|
| **Broken Access Control** | `accessControlDetection` | Detects privilege escalation attempts and unauthorized resource access. | `true` |
| **Cryptographic Failures** | `cryptographicValidation` | Checks for weak encryption usage and exposure of sensitive data in transit. | `true` |
| **Security Headers** | `securityHeadersValidation` | Validates security headers (CSP, HSTS, X-Frame-Options) to prevent misconfigurations. | `true` |
| **Vulnerable Components** | `vulnerableComponentsDetection` | Identifies usage of known vulnerable dependencies or components. | `true` |
| **Auth Failures** | `authenticationValidation` | Detects weak authentication mechanisms and brute-force attempts. | `true` |
| **Integrity Failures** | `softwareIntegrityValidation` | Verifies integrity of software updates and critical data flows. | `true` |
| **Logging Failures** | `auditLogging` | Ensures critical security events are logged for audit trails. | `true` |
| **SSRF** | `ssrfDetection` | Server-Side Request Forgery prevention - blocks requests to internal networks/localhost. | `true` |
| **Injection** | *Covered by `sqliDetection`* | (See Core Security) | `true` |

### Advanced Security

Specialized protection for modern applications and APIs.

| Feature | Key | Description | Default |
|---------|-----|-------------|---------|
| **CSRF** | `csrfDetection` | Cross-Site Request Forgery protection. Verifies Origin/Referer headers for state-changing requests. | `true` |
| **IDOR** | `idorDetection` | Insecure Direct Object Reference detection. Checks for unauthorized access to objects via IDs. | `true` |
| **Host Header Injection** | `hostHeaderInjectionDetection` | Prevents attacks that manipulate the Host header to poison caches or reset passwords. | `true` |
| **Data Leakage** | `dataLeakageDetection` | Scans outgoing responses for sensitive data (API keys, Credit Cards, SSN, PII). | `true` |
| **Session Anomalies** | `sessionAnomaliesDetection` | Behavioral analysis to detect session hijacking and unusual user patterns. | `true` |
| **API Validation** | `apiSchemaValidation` | Validates requests against expected API schemas and structures. | `true` |
| **File Upload** | `fileUploadDetection` | Scans uploaded files for malware and validates file types/extensions. | `true` |
| **Third Party** | `thirdPartyDetection` | Monitors and validates interactions with third-party APIs and services. | `true` |
| **Compliance** | `complianceDetection` | Checks for violations of GDPR, HIPAA, and other regulatory requirements. | `true` |
| **Threat Intel** | `threatIntelligence` | Checks IPs and signatures against global threat intelligence feeds. | `true` |
| **Zero Trust** | `zeroTrustDetection` | Enforces strict verification for every request, assuming no trust by default. | `true` |

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
  // Required
  apiKey: process.env.SILKER_API_KEY!,
  
  // Optional Main Options
  appId: 'd6bd4319-5aa9-49c8-b760-b4dfce661cbc',
  endpoint: 'https://api.silkerai.com',
  debug: false,
  maxPayloadSize: 1048576, // 1MB

  // Feature Toggles (All default to true)
  features: {
    // Core
    rateLimit: true,
    sqliDetection: true,
    xssDetection: true,
    pathTraversalDetection: true,
    promptInjectionDetection: true,
    ipBanning: true,

    // OWASP
    accessControlDetection: true,
    cryptographicValidation: true,
    securityHeadersValidation: true,
    vulnerableComponentsDetection: true,
    authenticationValidation: true,
    softwareIntegrityValidation: true,
    auditLogging: true,
    ssrfDetection: true,

    // Advanced
    csrfDetection: true,
    idorDetection: true,
    hostHeaderInjectionDetection: true,
    dataLeakageDetection: true,
    sessionAnomaliesDetection: true,
    apiSchemaValidation: true,
    fileUploadDetection: true,
    thirdPartyDetection: true,
    complianceDetection: true,
    threatIntelligence: true,
    zeroTrustDetection: true,
    cloudCommunication: true
  }
}));

app.listen(3000);
```

### 2. Development Mode

Optimized for local development with verbose logging.

```typescript
app.use(middleware({
  apiKey: process.env.SILKER_API_KEY!,
  appId: 'dev-app',
  endpoint: 'http://localhost:3000', // Local backend
  debug: true,                       // Verbose logging
  features: {
    // Disable heavy features for faster dev loop
    threatIntelligence: false,
    sessionAnomaliesDetection: false,
    apiSchemaValidation: false
  }
}));
```

### 3. Production Mode

Optimized for security and performance.

```typescript
app.use(middleware({
  apiKey: process.env.SILKER_API_KEY!,
  appId: 'prod-app',
  endpoint: 'https://api.silkerai.com',
  debug: false,
  maxPayloadSize: 102400, // 100KB
  // All features enabled by default
}));
```

### 4. Selective Protection (API Gateway)

Enabling only specific checks for a gateway service.

```typescript
app.use(middleware({
  apiKey: process.env.SILKER_API_KEY!,
  appId: 'gateway',
  features: {
    // Enable only these
    rateLimit: true,
    sqliDetection: true,
    xssDetection: true,
    
    // Disable everything else
    pathTraversalDetection: false,
    promptInjectionDetection: false,
    accessControlDetection: false,
    cryptographicValidation: false,
    securityHeadersValidation: false,
    vulnerableComponentsDetection: false,
    authenticationValidation: false,
    softwareIntegrityValidation: false,
    auditLogging: false,
    ssrfDetection: false,
    csrfDetection: false,
    idorDetection: false,
    hostHeaderInjectionDetection: false,
    dataLeakageDetection: false,
    sessionAnomaliesDetection: false,
    apiSchemaValidation: false,
    fileUploadDetection: false,
    thirdPartyDetection: false,
    complianceDetection: false,
    threatIntelligence: false,
    zeroTrustDetection: false,
    cloudCommunication: false
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

### Optional Environment Variables

```bash
# Application ID (recommended for multi-app setups)
SILKER_APP_ID=d6bd4319-5aa9-49c8-b760-b4dfce661cbc

# Custom endpoint (optional)
SILKER_ENDPOINT=https://api.silkerai.com

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
| `apiSchemaValidation` | Medium (validation) |
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
- **API Reference**: [https://api.silkerai.com/docs](https://api.silkerai.com/docs)
- **GitHub**: [https://github.com/silker/agent](https://github.com/silker/agent)
- **Issues**: [https://github.com/silker/agent/issues](https://github.com/silker/agent/issues)

---

## License

UNLICENSED - Proprietary Software

Copyright © 2024 Silker AI. All rights reserved.
