# Silker Agent - Configuration Guide

Complete configuration reference for `@silker-ai/agent` v1.0.2+

---

## Table of Contents

- [Quick Start](#quick-start)
- [Main Options](#main-options)
- [Security Features](#security-features)
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

**This is all you need to get started.** All security features are enabled by default.

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
| `endpoint` | `string` | Auto | API endpoint URL (see defaults below) |
| `debug` | `boolean` | `false` | Enable detailed console logging |
| `maxPayloadSize` | `number` | `51200` | Maximum payload size to scan (bytes) |
| `features` | `object` | All enabled | Feature toggles (see below) |

### Endpoint Defaults

The SDK automatically selects the correct endpoint:

- **Development** (`NODE_ENV=development`): `http://localhost:3000`
- **Production**: `https://api.silkerai.com`
- **Custom**: Set explicitly via `endpoint` option

---

## Security Features

All features are **enabled by default** (opt-out model). Set to `false` to disable.

### Core Security (5 features)

```typescript
features: {
  rateLimit: true,                      // Rate limiting (5 req/min per IP)
  sqliDetection: true,                  // SQL Injection detection
  xssDetection: true,                   // Cross-Site Scripting (XSS) detection
  pathTraversalDetection: true,         // Directory traversal attacks
  promptInjectionDetection: true,       // AI/LLM prompt injection
}
```

### OWASP Top 10 (10 features)

```typescript
features: {
  accessControlDetection: true,         // A01: Broken Access Control
  cryptographicValidation: true,        // A02: Cryptographic Failures
  // sqliDetection (covered in Core)    // A03: Injection
  securityHeadersValidation: true,      // A04: Insecure Design + A05: Security Misconfiguration
  vulnerableComponentsDetection: true,  // A06: Vulnerable Components
  authenticationValidation: true,       // A07: Authentication Failures
  softwareIntegrityValidation: true,    // A08: Software Integrity Failures
  auditLogging: true,                   // A09: Logging & Monitoring Failures
  ssrfDetection: true,                  // A10: Server-Side Request Forgery
}
```

### Advanced Security (12 features)

```typescript
features: {
  csrfDetection: true,                  // Cross-Site Request Forgery
  idorDetection: true,                  // Insecure Direct Object References
  hostHeaderInjectionDetection: true,   // Host header manipulation
  dataLeakageDetection: true,           // API keys, PII, credit cards, SSN
  sessionAnomaliesDetection: true,      // Unusual session behavior & bot detection
  apiSchemaValidation: true,            // API schema & OpenAPI compliance
  fileUploadDetection: true,            // Malicious file uploads & malware
  thirdPartyDetection: true,            // Risky external integrations
  complianceDetection: true,            // GDPR, HIPAA violations
  threatIntelligence: true,             // Known malicious IPs/patterns
  zeroTrustDetection: true,             // Zero-trust policy enforcement
  cloudCommunication: true,             // Send events to cloud backend
}
```

### Feature Summary

| Category | Count | Default |
|----------|-------|---------|
| **Core Security** | 5 | All enabled |
| **OWASP Top 10** | 10 | All enabled |
| **Advanced Security** | 12 | All enabled |
| **Total** | **25 features** | **All enabled** |

---

## Complete Examples

### 1. Express.js (Recommended)

```typescript
import express from 'express';
import { middleware } from '@silker-ai/agent';

const app = express();

app.use(middleware({
  apiKey: process.env.SILKER_API_KEY!,
  appId: 'd6bd4319-5aa9-49c8-b760-b4dfce661cbc',
  endpoint: 'https://api.silkerai.com',
  debug: false,
  maxPayloadSize: 51200,
  features: {
    rateLimit: true,
    sqliDetection: true,
    xssDetection: true,
    pathTraversalDetection: true,
    promptInjectionDetection: true,
    accessControlDetection: true,
    cryptographicValidation: true,
    securityHeadersValidation: true,
    vulnerableComponentsDetection: true,
    authenticationValidation: true,
    softwareIntegrityValidation: true,
    auditLogging: true,
    ssrfDetection: true,
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
    cloudCommunication: true,
  }
}));

app.listen(3000);
```

### 2. Next.js App Router

Create `middleware.ts` in your project root:

```typescript
import { middleware } from '@silker-ai/agent';

export const config = {
  matcher: '/api/:path*'
};

export default middleware({
  apiKey: process.env.SILKER_API_KEY!,
  appId: process.env.SILKER_APP_ID!,
  debug: process.env.NODE_ENV === 'development',
  features: {
    // All features enabled by default
    // Disable specific features if needed:
    // threatIntelligence: false,
  }
});
```

### 3. Production-Optimized

```typescript
app.use(middleware({
  apiKey: process.env.SILKER_API_KEY!,
  appId: process.env.SILKER_APP_ID!,
  endpoint: process.env.SILKER_ENDPOINT || 'https://api.silkerai.com',
  debug: false,
  maxPayloadSize: 102400, // 100KB
  features: {
    // Core protection - always enabled
    rateLimit: true,
    sqliDetection: true,
    xssDetection: true,
    pathTraversalDetection: true,
    promptInjectionDetection: true,
    
    // OWASP Top 10 - enabled
    accessControlDetection: true,
    cryptographicValidation: true,
    securityHeadersValidation: true,
    ssrfDetection: true,
    csrfDetection: true,
    idorDetection: true,
    
    // Advanced - enabled for production
    dataLeakageDetection: true,
    threatIntelligence: true,
    cloudCommunication: true,
    auditLogging: true,
    
    // Optional - disable if not needed
    fileUploadDetection: false,
    thirdPartyDetection: false,
    complianceDetection: false,
  }
}));
```

### 4. Development Mode

```typescript
app.use(middleware({
  apiKey: process.env.SILKER_API_KEY!,
  appId: 'dev-app',
  endpoint: 'http://localhost:3000',
  debug: true, // Enable detailed logging
  maxPayloadSize: 51200,
  features: {
    // Enable only essential features for faster development
    rateLimit: true,
    sqliDetection: true,
    xssDetection: true,
    pathTraversalDetection: true,
    
    // Disable heavy features
    threatIntelligence: false,
    sessionAnomaliesDetection: false,
    apiSchemaValidation: false,
    cloudCommunication: false,
  }
}));
```

### 5. Selective Protection

Enable only specific security features:

```typescript
app.use(middleware({
  apiKey: process.env.SILKER_API_KEY!,
  appId: 'api-gateway',
  features: {
    // Disable all by default
    rateLimit: true,
    sqliDetection: true,
    xssDetection: true,
    csrfDetection: true,
    
    // Everything else disabled
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
    cloudCommunication: false,
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

### Example .env.development

```bash
SILKER_API_KEY=sk_dev_test_key
SILKER_APP_ID=dev-app-001
SILKER_ENDPOINT=http://localhost:3000
NODE_ENV=development
```

### Example .env.production

```bash
SILKER_API_KEY=sk_prod_live_key
SILKER_APP_ID=prod-app-001
SILKER_ENDPOINT=https://api.silkerai.com
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

## Feature Defaults Reference

**All features are enabled by default.** You only need to specify features you want to **disable**.

```typescript
// This:
app.use(middleware({
  apiKey: 'sk_...'
}));

// Is equivalent to:
app.use(middleware({
  apiKey: 'sk_...',
  debug: false,
  maxPayloadSize: 51200,
  features: {
    rateLimit: true,
    sqliDetection: true,
    xssDetection: true,
    pathTraversalDetection: true,
    promptInjectionDetection: true,
    accessControlDetection: true,
    cryptographicValidation: true,
    securityHeadersValidation: true,
    vulnerableComponentsDetection: true,
    authenticationValidation: true,
    softwareIntegrityValidation: true,
    auditLogging: true,
    ssrfDetection: true,
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
    cloudCommunication: true,
  }
}));
```

---

## Performance Considerations

### maxPayloadSize

- **Default**: 51200 bytes (50KB)
- **Recommended**: 51200 - 102400 bytes (50-100KB)
- **Impact**: Larger payloads = slower scanning
- **Best Practice**: Set to the maximum expected request size

```typescript
maxPayloadSize: 51200   // Fast  - 50KB
maxPayloadSize: 102400  // Medium - 100KB
maxPayloadSize: 524288  // Slow  - 500KB
```

### Feature Impact

| Feature | Performance Impact |
|---------|-------------------|
| `rateLimit` | Very Low |
| `sqliDetection` | Low |
| `xssDetection` | Low |
| `pathTraversalDetection` | Very Low |
| `promptInjectionDetection` | Low |
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
  endpoint: 'https://silkerai.com',
  debug: true,
  maxPayloadSize: 51200,
- dashboardUrl: 'https://dash.silker.ai',  // ❌ REMOVED - use endpoint
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
