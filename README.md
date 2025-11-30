# @silker/ai-sdk

**Production-Ready Runtime Security Agent** for AI-powered applications. Detects anomalies, blocks attacks, and provides real-time protection with intelligent insights.

Perfect for Cursor, Bubble, Next.js on Vercel, and any Node.js app that needs runtime security without the heavy lifting.

> **Dokumentacja w języku polskim**: [README.pl.md](README.pl.md)

## ✨ Features (v1.0.0)

### 🧠 Next-Gen Detection Engine
- **Heuristic Analysis** - Replaces legacy regexes with smart tokenization for SQLi & XSS.
- **Zero False Positives** - Drastically reduced false alarm rate for legitimate traffic.
- **ReDoS Protection** - Immune to Regular Expression Denial of Service attacks.
- **High Performance** - Optimized for high-throughput Node.js applications.

### 🛡️ Advanced AI Security
- **Prompt Injection Shield** - Detects jailbreaks (DAN, etc.), role manipulation, and instruction overrides.
- **Token Smuggling Detection** - Identifies obfuscation attempts using invisible characters or unicode hacks.
- **Fuzzy Matching** - Catches "D A N" and other spaced-out attack vectors.
- **Large Context Support** - Optimized for RAG and long-context LLM applications (up to 50KB payloads).

### Core Security
- 🚦 **Rate Limiting Detection** - Blocks brute-force attempts (>5 req/min per IP)
- 🛡️ **Payload Sanity Checks** - Detects SQLi, XSS, and malicious patterns
- 🔒 **Path Traversal Protection** - Prevents directory traversal (`../`)
- 🎯 **Anomaly Detection** - Custom rules for suspicious activity

### OWASP Top 10 Protection
- 🛡️ **CSRF Protection** - Detects missing CSRF tokens
- 🌐 **SSRF Prevention** - Blocks requests to internal networks and cloud metadata
- 🔐 **IDOR Detection** - Identifies insecure direct object reference attacks
- 📋 **Host Header Injection Protection** - Prevents host header manipulation
- 🔒 **Security Headers Validation** - Validates presence of security headers

### Advanced Security Features
- 🔍 **Data Leakage Prevention** - Scans for API keys, PII, and secrets
- 🤖 **User Behavior Analytics** - Bot detection and session anomaly analysis
- 📊 **API Schema Validation** - Validates API structure and OpenAPI compliance
- 📁 **File Upload Security** - Malware scanning and file type validation
- 🔗 **Third-party Integration Security** - Monitors external API calls and webhooks
- ⚖️ **Compliance Monitoring** - GDPR, HIPAA, and data protection compliance
- 🕵️ **Threat Intelligence** - Real-time blocking based on threat feeds
- 🔐 **Zero-trust Verification** - Continuous verification of all operations
- 🧠 **Prompt Injection Protection** - Detects AI/LLM jailbreak and manipulation attempts

### Monitoring & Analytics
- ⚡ **Performance Monitoring** - Detects performance anomalies and slow endpoints
- 📝 **Advanced Audit Logging** - Comprehensive security event logging
- ⚙️ **Runtime Configuration Management** - Real-time configuration updates
- 💚 **Health Checks** - Agent health monitoring and self-diagnostics

### Integration & Deployment
- ☁️ **Cloud Integration** - Real-time alerts to Cloudflare Workers + Grok AI
- 🌐 **Proxy Mode** - CNAME setup support for advanced deployments
- 🎣 **Auto-Hooks** - Seamless integration with fetch, Express, and custom workflows
- 🔒 **Data Sanitization** - Automatic masking of sensitive data before sending
- ⚡ **Self-contained** - ~63KB gzipped, all dependencies bundled
- 🤐 **Silent by Default** - Won't pollute your production logs unless configured

## Installation

```bash
npm install @silker/ai-sdk
```

## Compatibility

Silker AI SDK works with **any Node.js runtime** (server-side):

### Fully Supported

- **Node.js** (v14+) - All features work
- **Next.js** (Server-side / API Routes) - Full support via `SilkerAI.init()` and `middleware()`
- **Express.js** - Full support via `middleware()` 
- **Fastify** - Works with Express middleware adapter
- **Koa.js** - Works with Express middleware adapter
- **NestJS** - Works as Express middleware
- **SvelteKit** - Server-side API routes
- **Remix** - Server-side loaders/actions
- **Nuxt.js** - Server-side API routes
- **Cloudflare Workers** - Limited (no `process.env`, use `env` parameter)
- **Vercel Edge Functions** - Limited (no `process.env`, use `env` parameter)
- **AWS Lambda** - Full support
- **Google Cloud Functions** - Full support
- **Azure Functions** - Full support

### Limited Support

- **Browser/Client-side** - Only `hookFetch()` works, no `process.env`, no health checks
- **Deno** - Not tested, may require adjustments
- **Bun** - Should work but not officially tested

### Requirements

- **Node.js**: >= 14.0.0
- **Runtime**: Server-side Node.js environment
- **Dependencies**: axios, events, http-proxy (bundled)

### Framework-Specific Examples

#### Next.js (App Router)

```typescript
// app/api/route.ts or middleware.ts
import SilkerAI from '@silker/ai-sdk';

await SilkerAI.init({
  apiKey: process.env.SILKER_API_KEY!
});

export const config = {
  matcher: '/api/:path*'
};

export default SilkerAI.middleware({ apiKey: process.env.SILKER_API_KEY! });
```

#### Next.js (Pages Router)

```typescript
// pages/_middleware.ts or pages/api/[...route].ts
import SilkerAI from '@silker/ai-sdk';

await SilkerAI.init({
  apiKey: process.env.SILKER_API_KEY!
});

export default SilkerAI.middleware({ apiKey: process.env.SILKER_API_KEY! });
```

#### Express.js

```typescript
import express from 'express';
import SilkerAI from '@silker/ai-sdk';

const app = express();
const options = { apiKey: process.env.SILKER_API_KEY! };

await SilkerAI.init(options);
app.use(SilkerAI.middleware(options));
```

#### Fastify

```typescript
import fastify from 'fastify';
import SilkerAI from '@silker/ai-sdk';

await SilkerAI.init({ apiKey: process.env.SILKER_API_KEY! });

// Use @fastify/express adapter or manual request interception
// Fastify uses Express-compatible middleware
```

#### Cloudflare Workers / Vercel Edge

```typescript
// Note: Use env parameter instead of process.env
import SilkerAI from '@silker/ai-sdk';

export default {
  async fetch(request: Request, env: any) {
    await SilkerAI.init({
      apiKey: env.SILKER_API_KEY,
      features: { cloudCommunication: true }
    });
    
    // Your worker logic...
  }
};
```

## Quick Start

### Basic Setup

```typescript
import SilkerAI from '@silker/ai-sdk';

// Initialize with your API key from environment variable
await SilkerAI.init({
  apiKey: process.env.SILKER_API_KEY!,
  // debug: true // Uncomment to enable verbose logging (default: silent)
});

// That's it! Your app is now protected
// API calls via fetch() are automatically monitored
```

**Security Note**: Never hardcode API keys in your code. Always use environment variables:
```bash
export SILKER_API_KEY="your-api-key-here"
```

### Express.js Integration

```typescript
import express from 'express';
import SilkerAI from '@silker/ai-sdk';

const app = express();

const options = { apiKey: process.env.SILKER_API_KEY! };

await SilkerAI.init(options);

// Add middleware for Express-specific monitoring
app.use(SilkerAI.middleware(options));

app.post('/api/login', (req, res) => {
  // Silker AI automatically scans requests
  res.json({ success: true });
});
```

### Custom Workflow Monitoring

```typescript
import SilkerAI from '@silker/ai-sdk';

// Monitor custom business logic
function processPayment(amount: number, userId: string) {
  SilkerAI.emitWorkflowEvent({
    method: 'POST',
    url: `/payments/${userId}`,
    payload: { amount },
    ip: 'user-ip-here'
  });

  // Your payment logic...
}
```

### Proxy Mode (Advanced)

For CNAME setups or when you need to proxy traffic through Silker AI:

```bash
# Set environment variables
export SILKER_TARGET_URL="http://your-app.com"
export SILKER_PROXY_PORT="8080"

# Enable proxy mode
await SilkerAI.init({
  apiKey: process.env.SILKER_API_KEY!,
  proxyMode: true
});
```

Then point your domain to `http://localhost:8080` and Silker AI will proxy all requests with security scanning.

### Performance Monitoring

```typescript
import SilkerAI from '@silker/ai-sdk';

// Record performance metrics
SilkerAI.recordPerformanceMetrics(event, responseTime, statusCode);

// Get performance report
const report = SilkerAI.getPerformanceReport();
console.log('Average response time:', report.summary.averageResponseTime);
console.log('Slow requests:', report.summary.slowRequests);
console.log('Anomalies:', report.anomalies);
```

### Audit Logging

```typescript
import SilkerAI from '@silker/ai-sdk';

// Log audit event
SilkerAI.logAuditEvent(event, 'blocked', 'SQL injection detected', 'high');

// Get audit logs with filters
const criticalLogs = SilkerAI.getAuditLogs(50, 'critical', 'blocked');

// Get audit summary
const summary = SilkerAI.getAuditSummary();
console.log('Total logs:', summary.totalLogs);
console.log('Severity breakdown:', summary.severityBreakdown);
```

### Runtime Configuration Management

```typescript
import SilkerAI from '@silker/ai-sdk';

// Get current configuration
const config = SilkerAI.getRuntimeConfig();
console.log('Rate limit threshold:', config.rateLimitThreshold);

// Update configuration at runtime
const result = SilkerAI.updateRuntimeConfig({
  rateLimitThreshold: 10,
  slowRequestThreshold: 3000,
  debug: true
});
console.log('Updated keys:', result.updated);
```

### Health Checks

```typescript
import SilkerAI from '@silker/ai-sdk';

// Perform health check
const health = SilkerAI.performHealthCheck();
console.log('Status:', health.status); // 'healthy' | 'degraded' | 'unhealthy'
console.log('Memory:', health.checks.memory.usage, 'MB');
console.log('Uptime:', health.uptime, 'ms');
```

### User Behavior Analysis

```typescript
import SilkerAI from '@silker/ai-sdk';

// Analyze user behavior
const behavior = SilkerAI.analyzeUserBehavior(event);
if (behavior.isAnomalous) {
  console.log('Anomalies detected:', behavior.reasons);
  console.log('Anomaly score:', behavior.score);
}
```

### API Validation

```typescript
import SilkerAI from '@silker/ai-sdk';

// Validate API schema
const apiValidation = SilkerAI.performApiValidation(event);
if (!apiValidation.valid) {
  console.log('API warnings:', apiValidation.warnings);
}

// Validate security headers
const headerValidation = SilkerAI.validateSecurityHeaders(req.headers);
if (!headerValidation.valid) {
  console.log('Missing headers:', headerValidation.missing);
}
```

## Configuration Options

```typescript
interface SilkerOptions {
  apiKey: string;          // Required: Your Silker AI API key
  endpoint?: string;       // Optional: Custom cloud endpoint (default: Cloudflare Workers)
  debug?: boolean;         // Optional: Enable console logging
  proxyMode?: boolean;     // Optional: Enable proxy mode for CNAME setups
  features?: SilkerFeatures; // Optional: Enable/disable specific features
  maxPayloadSize?: number; // Optional: Limit payload size for scanning (bytes), default 50KB
  logger?: Logger;         // Optional: Provide custom logger implementation
}

interface Logger {
    info(message: string, ...args: any[]): void;
    warn(message: string, ...args: any[]): void;
    error(message: string, ...args: any[]): void;
    debug(message: string, ...args: any[]): void;
}

interface SilkerFeatures {
  rateLimit?: boolean;                      // Rate limiting detection
  sqliDetection?: boolean;                 // SQL injection detection
  xssDetection?: boolean;                  // XSS attack detection
  pathTraversalDetection?: boolean;        // Path traversal protection
  csrfDetection?: boolean;                 // CSRF protection
  ssrfDetection?: boolean;                 // SSRF prevention
  idorDetection?: boolean;                 // IDOR detection
  hostHeaderInjectionDetection?: boolean;  // Host header injection protection
  securityHeadersValidation?: boolean;    // Security headers validation
  dataLeakageDetection?: boolean;         // Data leakage prevention
  apiSchemaValidation?: boolean;           // API schema validation
  sessionAnomaliesDetection?: boolean;    // Session anomalies detection
  fileUploadDetection?: boolean;          // File upload security
  thirdPartyDetection?: boolean;          // Third-party integration security
  complianceDetection?: boolean;          // Compliance monitoring
  threatIntelligence?: boolean;           // Threat intelligence
  zeroTrustDetection?: boolean;           // Zero-trust verification
  promptInjectionDetection?: boolean;     // Prompt injection protection (AI/LLM)
  auditLogging?: boolean;                  // Audit logging
  performanceMonitoring?: boolean;       // Performance monitoring
  cloudCommunication?: boolean;          // Cloud communication
}
```

### Feature Toggle Example

You can enable or disable specific security features:

```typescript
import SilkerAI from '@silker/ai-sdk';

await SilkerAI.init({
  apiKey: process.env.SILKER_API_KEY!,
  features: {
    rateLimit: true,              // Enable rate limiting
    sqliDetection: true,          // Enable SQL injection detection
    xssDetection: false,          // Disable XSS detection
    promptInjectionDetection: true, // Enable prompt injection protection
    auditLogging: true,           // Enable audit logging
    cloudCommunication: true     // Enable cloud communication
  }
});
```

By default, all features are **enabled** (backward compatible). Set a feature to `false` to disable it.

**Security Best Practices:**
- Always use environment variables for API keys: `process.env.SILKER_API_KEY`
- Never commit API keys to version control
- Use `.env` files (add to `.gitignore`) for local development
- Use secure secret management in production (AWS Secrets Manager, Vercel Environment Variables, etc.)

## Security Features

### Core Security Engine
- **Rate Limiting**: Blocks IPs exceeding 5 requests per minute
- **SQL Injection**: Detects common SQLi patterns in payloads
- **XSS Attacks**: Scans for script injection attempts
- **Path Traversal**: Prevents `../` directory traversal
- **Suspicious IPs**: Flags unusual traffic patterns

### OWASP Top 10 Protection
- **CSRF Protection**: Detects missing CSRF tokens in state-changing requests
- **SSRF Prevention**: Blocks requests to internal/private networks and cloud metadata
- **IDOR Detection**: Identifies insecure direct object reference attacks
- **Host Header Injection**: Prevents host header manipulation attacks
- **Security Headers**: Validates presence of essential security headers

### Advanced Security Features
- **Data Leakage Prevention**: Scans for API keys, PII, and sensitive data exposure
  - Detects API keys in payloads and responses
  - Scans for personally identifiable information (SSN, credit cards, emails)
  - Detects secrets and tokens
  - Identifies database credentials
- **User Behavior Analytics**: Bot detection and session anomaly analysis
  - Bot detection based on request regularity
  - Analysis of time intervals between requests
  - Detects suspicious HTTP method combinations
  - Identifies excessive API endpoint access
  - Analyzes session length and activity
- **API Schema Validation**: Validates API structure and OpenAPI compliance
  - Validates required fields for user/account endpoints
  - Email format checking
  - API response structure validation
  - OpenAPI convention compliance
  - URL parameters and query string validation
- **File Upload Security**: Malware scanning and file type validation
  - Magic byte checking (file signatures)
  - MIME type validation
  - Executable file detection
  - File size checking (max 10MB)
  - Dangerous filename detection
  - Path traversal protection in filenames
- **Third-party Integration Security**: Monitors external API calls and webhooks
  - Detects suspicious domains (pastebin, transfer.sh, ngrok)
  - Webhook and callback validation
  - API key exposure detection in external requests
  - Large payload monitoring in external requests
  - Sensitive data detection in integrations
- **Compliance Monitoring**: GDPR, HIPAA, and data protection compliance
  - Detects PII processing without GDPR consent
  - Data retention policy verification
  - Medical data detection without HIPAA authorization
  - TLS encryption requirement for health data
  - Sensitive data classification
- **Threat Intelligence**: Real-time blocking based on threat feeds
  - Known malicious IP database
  - Malicious domain list
  - Security scanner detection (sqlmap, nikto, dirbuster)
  - Suspicious user-agent identification
- **Zero-trust Verification**: Continuous verification of all operations
  - Authentication required for all requests
  - Request origin verification (Origin/Referer)
  - Device verification (User-Agent)
  - Additional confirmations for destructive operations (DELETE)
  - Off-hours access verification
- **Prompt Injection Protection**: AI/LLM security for modern applications
  - Instruction override detection (ignore, disregard, forget)
  - System prompt manipulation blocking
  - Role manipulation prevention
  - Delimiter injection detection (```, ---, ###, special tokens)
  - Jailbreak attempt detection (DAN mode, unrestricted access)
  - Prompt extraction prevention
  - Encoding obfuscation detection (base64, unicode, hex)
  - Chain manipulation blocking
  - Multilingual attack detection
  - Severity scoring (low, medium, high, critical)

### Enterprise Monitoring Features
- **Performance Monitoring**: Detects performance anomalies and slow endpoints
  - Tracks response time for each endpoint
  - Detects slow requests (>5s)
  - Analyzes average response time
  - Identifies slow endpoints (>3s average)
- **Advanced Audit Logging**: Comprehensive security event logging for compliance
  - Logs all actions (allowed, blocked, flagged)
  - Severity levels (low, medium, high, critical)
  - Filtering and search capabilities
  - Statistical summaries
- **Configuration Management API**: Runtime configuration updates
  - Dynamic rate limit threshold changes
  - Slow request threshold configuration
  - Enable/disable monitoring features
  - Custom security rules
- **Health Checks**: Agent health monitoring and self-diagnostics
  - Memory status (heap usage)
  - Performance status (average response time)
  - Security status (recent blocks)
  - Cloud connectivity status
  - System uptime

### Response Handling

When anomalies are detected:

1. **Block Request**: Returns 403 Forbidden with alert ID
2. **Cloud Alert**: Sends metadata to your backend for AI analysis
3. **Graceful Degradation**: Never breaks your app - fails safely

## Cloud Integration

Silker AI communicates with your Cloudflare Workers backend:

```typescript
// Example cloud response
{
  block: true,           // Whether to block the request
  fixSnippet?: string,   // AI-generated fix suggestion
  severity: 'high',      // low | medium | high
  alertId: 'alert-123'   // Unique alert identifier
}
```

### Data Sanitization

Silker AI automatically sanitizes sensitive data before sending to cloud:
- Passwords and secrets are masked
- Tokens and API keys are hidden
- Personal data is protected
- Database connection strings are masked

## API Reference

### Exported Functions

```typescript
// Initialization
SilkerAI.init(options: SilkerOptions): Promise<void>
SilkerAI.emitWorkflowEvent(event: Omit<SilkerEvent, 'timestamp'>): void

// Express middleware
SilkerAI.middleware(options: SilkerOptions): (req, res, next) => Promise<void>

// Performance monitoring
SilkerAI.recordPerformanceMetrics(event: SilkerEvent, responseTime: number, statusCode?: number): void
SilkerAI.getPerformanceReport(): PerformanceReport

// Audit
SilkerAI.logAuditEvent(event: SilkerEvent, action: 'allowed' | 'blocked' | 'flagged', reason: string, severity?: 'low' | 'medium' | 'high' | 'critical', metadata?: any): void
SilkerAI.getAuditLogs(limit?: number, severity?: string, action?: string): AuditLogEntry[]
SilkerAI.getAuditSummary(): AuditSummary

// Configuration
SilkerAI.getRuntimeConfig(): RuntimeConfig
SilkerAI.updateRuntimeConfig(updates: Partial<RuntimeConfig>): { success: boolean; updated: string[] }

// Health check
SilkerAI.performHealthCheck(): HealthStatus

// Cloud communication
SilkerAI.sendToCloud(event: SilkerEvent, options: SilkerOptions): Promise<CloudResponse | null>
```

### Types

```typescript
interface SilkerOptions {
  apiKey: string;
  endpoint?: string;
  debug?: boolean;
  proxyMode?: boolean;
  features?: SilkerFeatures;
}

interface SilkerFeatures {
  rateLimit?: boolean;
  sqliDetection?: boolean;
  xssDetection?: boolean;
  pathTraversalDetection?: boolean;
  csrfDetection?: boolean;
  ssrfDetection?: boolean;
  idorDetection?: boolean;
  hostHeaderInjectionDetection?: boolean;
  securityHeadersValidation?: boolean;
  dataLeakageDetection?: boolean;
  apiSchemaValidation?: boolean;
  sessionAnomaliesDetection?: boolean;
  fileUploadDetection?: boolean;
  thirdPartyDetection?: boolean;
  complianceDetection?: boolean;
  threatIntelligence?: boolean;
  zeroTrustDetection?: boolean;
  promptInjectionDetection?: boolean;
  auditLogging?: boolean;
  performanceMonitoring?: boolean;
  cloudCommunication?: boolean;
}

interface SilkerEvent {
  method: string;
  url: string;
  payload?: any;
  ip?: string;
  timestamp: number;
  userAgent?: string;
  headers?: Record<string, string>;
}

interface CloudResponse {
  block: boolean;
  fixSnippet?: string;
  severity?: 'low' | 'medium' | 'high';
  alertId?: string;
}

interface RuntimeConfig {
  debug: boolean;
  proxyMode: boolean;
  rateLimitThreshold: number;
  slowRequestThreshold: number;
  enableAuditLogging: boolean;
  enablePerformanceMonitoring: boolean;
  customRules: any[];
}

interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: number;
  checks: {
    memory: { status: 'ok' | 'warning' | 'error'; usage: number };
    performance: { status: 'ok' | 'warning' | 'error'; avgResponseTime: number };
    security: { status: 'ok' | 'warning' | 'error'; recentBlocks: number };
    connectivity: { status: 'ok' | 'error'; lastCloudContact: number };
  };
  uptime: number;
  version: string;
}
```

## Testing

```bash
npm test
```

Tests cover:
- Agent initialization
- Anomaly detection (rate limiting, SQLi, XSS)
- Cloud communication
- Error handling

## Build & Publish

```bash
npm run build    # Compile TypeScript + bundle with esbuild
npm test         # Run test suite
npm publish      # Publish to npm registry
```

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Your App      │───▶│   Silker AI      │───▶│ Cloudflare + AI │
│                 │    │                  │    │                 │
│ • fetch() calls │    │ • Anomaly Detect │    │ • Real-time     │
│ • API routes    │    │ • Rate Limiting  │    │ • AI Analysis   │
│ • Workflows     │    │ • Payload Scan   │    │ • Alerting      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Contributing

Silker AI is built for the developer community. PRs welcome!

## License

MIT License

---

**Made by Silker AI**
