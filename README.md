# @silker-ai/ai-sdk

Runtime security agent for AI-powered applications. Detects anomalies, blocks attacks, provides real-time protection.

## Installation

```bash
npm install @silker-ai/ai-sdk
```

## Quick Start

```typescript
import SilkerAI from '@silker-ai/ai-sdk';

await SilkerAI.init({
  apiKey: process.env.SILKER_API_KEY!
});
```

### Express.js

```typescript
import express from 'express';
import SilkerAI from '@silker-ai/ai-sdk';

const app = express();
const options = { apiKey: process.env.SILKER_API_KEY! };

await SilkerAI.init(options);
app.use(SilkerAI.middleware(options));
```

## Features

- SQL Injection & XSS detection
- Rate limiting
- CSRF, SSRF, IDOR protection
- Prompt injection detection (AI/LLM security)
- Data leakage prevention
- File upload security
- Compliance monitoring (GDPR, HIPAA)
- Performance monitoring & audit logging

## Configuration

```typescript
await SilkerAI.init({
  apiKey: process.env.SILKER_API_KEY!,
  debug: false,
  features: {
    rateLimit: true,
    sqliDetection: true,
    xssDetection: true,
    promptInjectionDetection: true,
    cloudCommunication: true
  }
});
```

## Compatibility

Node.js 14+, Next.js, Express, Fastify, NestJS, AWS Lambda, Vercel, Cloudflare Workers.

## Documentation

Full documentation: [https://silker.ai/docs](https://silker.ai/docs)

## License

Proprietary - All Rights Reserved. See LICENSE file.

---

**Silker AI** - Runtime Security for Modern Apps
