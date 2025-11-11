# @vibeguard/agent

🛡️ **Lightweight Runtime Security Agent** for vibe-coding/no-code apps. Detects anomalies, blocks attacks, and alerts your cloud backend with AI-powered insights.

Perfect for Cursor, Bubble, Next.js on Vercel, and any Node.js app that needs runtime security without the heavy lifting.

> 📖 **Dokumentacja w języku polskim**: [README.pl.md](README.pl.md)

## ✨ Features

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

## 🚀 Installation

```bash
npm install @vibeguard/agent
```

## 🏁 Quick Start

### Basic Setup

```typescript
import { initVibeGuard } from '@vibeguard/agent';

// Initialize with your API key
await initVibeGuard({
  apiKey: 'your-api-key-here',
  debug: true // Optional: Enable debug logging
});

// That's it! Your app is now protected ✨
// API calls via fetch() are automatically monitored
```

### Express.js Integration

```typescript
import express from 'express';
import { initVibeGuard, middleware } from '@vibeguard/agent';

const app = express();

await initVibeGuard({ apiKey: 'your-api-key' });

// Add middleware for Express-specific monitoring
app.use(middleware({ apiKey: 'your-api-key' }));

app.post('/api/login', (req, res) => {
  // VibeGuard automatically scans requests
  res.json({ success: true });
});
```

### Custom Workflow Monitoring

```typescript
import { emitWorkflowEvent } from '@vibeguard/agent';

// Monitor custom business logic
function processPayment(amount: number, userId: string) {
  emitWorkflowEvent({
    method: 'POST',
    url: `/payments/${userId}`,
    payload: { amount },
    ip: 'user-ip-here'
  });

  // Your payment logic...
}
```

### Proxy Mode (Advanced)

For CNAME setups or when you need to proxy traffic through VibeGuard:

```bash
# Set environment variables
export VIBEGUARD_TARGET_URL="http://your-app.com"
export VIBEGUARD_PROXY_PORT="8080"

# Enable proxy mode
await initVibeGuard({
  apiKey: 'your-api-key',
  proxyMode: true
});
```

Then point your domain to `http://localhost:8080` and VibeGuard will proxy all requests with security scanning.

### Performance Monitoring

```typescript
import { recordPerformanceMetrics, getPerformanceReport } from '@vibeguard/agent';

// Record performance metrics
recordPerformanceMetrics(event, responseTime, statusCode);

// Get performance report
const report = getPerformanceReport();
console.log('Average response time:', report.summary.averageResponseTime);
console.log('Slow requests:', report.summary.slowRequests);
console.log('Anomalies:', report.anomalies);
```

### Audit Logging

```typescript
import { logAuditEvent, getAuditLogs, getAuditSummary } from '@vibeguard/agent';

// Log audit event
logAuditEvent(event, 'blocked', 'SQL injection detected', 'high');

// Get audit logs with filters
const criticalLogs = getAuditLogs(50, 'critical', 'blocked');

// Get audit summary
const summary = getAuditSummary();
console.log('Total logs:', summary.totalLogs);
console.log('Severity breakdown:', summary.severityBreakdown);
```

### Runtime Configuration Management

```typescript
import { getRuntimeConfig, updateRuntimeConfig } from '@vibeguard/agent';

// Get current configuration
const config = getRuntimeConfig();
console.log('Rate limit threshold:', config.rateLimitThreshold);

// Update configuration at runtime
const result = updateRuntimeConfig({
  rateLimitThreshold: 10,
  slowRequestThreshold: 3000,
  debug: true
});
console.log('Updated keys:', result.updated);
```

### Health Checks

```typescript
import { performHealthCheck } from '@vibeguard/agent';

// Perform health check
const health = performHealthCheck();
console.log('Status:', health.status); // 'healthy' | 'degraded' | 'unhealthy'
console.log('Memory:', health.checks.memory.usage, 'MB');
console.log('Uptime:', health.uptime, 'ms');
```

### User Behavior Analysis

```typescript
import { analyzeUserBehavior } from '@vibeguard/agent';

// Analyze user behavior
const behavior = analyzeUserBehavior(event);
if (behavior.isAnomalous) {
  console.log('Anomalies detected:', behavior.reasons);
  console.log('Anomaly score:', behavior.score);
}
```

### API Validation

```typescript
import { performApiValidation, validateSecurityHeaders } from '@vibeguard/agent';

// Validate API schema
const apiValidation = performApiValidation(event);
if (!apiValidation.valid) {
  console.log('API warnings:', apiValidation.warnings);
}

// Validate security headers
const headerValidation = validateSecurityHeaders(req.headers);
if (!headerValidation.valid) {
  console.log('Missing headers:', headerValidation.missing);
}
```

## 🔧 Configuration Options

```typescript
interface VibeGuardOptions {
  apiKey: string;          // Required: Your VibeGuard API key
  endpoint?: string;       // Optional: Custom cloud endpoint (default: Cloudflare Workers)
  debug?: boolean;         // Optional: Enable console logging
  proxyMode?: boolean;     // Optional: Enable proxy mode for CNAME setups
  features?: VibeGuardFeatures; // Optional: Enable/disable specific features
}

interface VibeGuardFeatures {
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
  auditLogging?: boolean;                  // Audit logging
  performanceMonitoring?: boolean;       // Performance monitoring
  cloudCommunication?: boolean;          // Cloud communication
}
```

### Feature Toggle Example

You can enable or disable specific security features:

```typescript
import { initVibeGuard } from '@vibeguard/agent';

await initVibeGuard({
  apiKey: 'your-api-key',
  features: {
    rateLimit: true,              // Enable rate limiting
    sqliDetection: true,          // Enable SQL injection detection
    xssDetection: false,          // Disable XSS detection
    auditLogging: true,           // Enable audit logging
    cloudCommunication: true     // Enable cloud communication
  }
});
```

By default, all features are **enabled** (backward compatible). Set a feature to `false` to disable it.

## 🛡️ Security Features

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

## 📡 Cloud Integration

VibeGuard communicates with your Cloudflare Workers backend:

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

VibeGuard automatically sanitizes sensitive data before sending to cloud:
- Passwords and secrets are masked
- Tokens and API keys are hidden
- Personal data is protected
- Database connection strings are masked

## 📚 API Reference

### Exported Functions

```typescript
// Initialization
initVibeGuard(options: VibeGuardOptions): Promise<void>
emitWorkflowEvent(event: Omit<VibeGuardEvent, 'timestamp'>): void

// Express middleware
middleware(options: VibeGuardOptions): (req, res, next) => Promise<void>

// Performance monitoring
recordPerformanceMetrics(event: VibeGuardEvent, responseTime: number, statusCode?: number): void
getPerformanceReport(): PerformanceReport

// Audit
logAuditEvent(event: VibeGuardEvent, action: 'allowed' | 'blocked' | 'flagged', reason: string, severity?: 'low' | 'medium' | 'high' | 'critical', metadata?: any): void
getAuditLogs(limit?: number, severity?: string, action?: string): AuditLogEntry[]
getAuditSummary(): AuditSummary

// Configuration
getRuntimeConfig(): RuntimeConfig
updateRuntimeConfig(updates: Partial<RuntimeConfig>): { success: boolean; updated: string[] }

// Health check
performHealthCheck(): HealthStatus

// Cloud communication
sendToCloud(event: VibeGuardEvent, options: VibeGuardOptions): Promise<CloudResponse | null>
```

### Types

```typescript
interface VibeGuardOptions {
  apiKey: string;
  endpoint?: string;
  debug?: boolean;
  proxyMode?: boolean;
  features?: VibeGuardFeatures;
}

interface VibeGuardFeatures {
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
  auditLogging?: boolean;
  performanceMonitoring?: boolean;
  cloudCommunication?: boolean;
}

interface VibeGuardEvent {
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

## 🧪 Testing

```bash
npm test
```

Tests cover:
- ✅ Agent initialization
- ✅ Anomaly detection (rate limiting, SQLi, XSS)
- ✅ Cloud communication
- ✅ Error handling

## 📦 Build & Publish

```bash
npm run build    # Compile TypeScript + bundle with esbuild
npm test         # Run test suite
npm publish      # Publish to npm registry
```

## 🎯 Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Your App      │───▶│  VibeGuard Agent │───▶│ Cloudflare + AI │
│                 │    │                  │    │                 │
│ • fetch() calls │    │ • Anomaly Detect │    │ • Real-time     │
│ • API routes    │    │ • Rate Limiting  │    │ • AI Analysis   │
│ • Workflows     │    │ • Payload Scan   │    │ • Alerting      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🤝 Contributing

VibeGuard is built with ❤️ for the developer community. PRs welcome!

## 📄 License

MIT License - Keep vibing safely! 🎉

---

**Made with ❤️ by VibeGuard AI - Security that doesn't suck**
