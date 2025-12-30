# @silker-ai/agent

**The Security Layer for AI-First Applications.**  
Silker AI is a lightweight, high-performance runtime security agent designed to protect modern JavaScript/TypeScript applications. It provides real-time protection against common web attacks and AI-specific threats without the complexity of a traditional WAF.

[![Version](https://img.shields.io/npm/v/@silker-ai/agent)](https://www.npmjs.com/package/@silker-ai/agent)
[![License](https://img.shields.io/npm/l/@silker-ai/agent)](https://github.com/silker/agent)

---

## 🚀 Why Silker AI?

Modern apps move fast, especially those powered by AI. Traditional security tools are often too slow, too heavy, or blind to AI-specific risks like prompt injection. Silker AI lives inside your application runtime, giving you:

- **Zero-Latency Protection**: Heuristic-based detection that blocks attacks in milliseconds.
- **AI Safety**: First-class protection against Prompt Injection and LLM manipulation.
- **Serverless Optimized**: Deeply integrated with Vercel and AWS Lambda to ensure 100% telemetry delivery.
- **Privacy First**: Sensitive data (PII, API keys) is automatically masked before leaving your server.

---

## 📦 Installation

```bash
npm install @silker-ai/agent
```

---

## 🔧 Quick Start

### Next.js (Server-side & API)
Silker AI automatically hooks into global `fetch` and provides middleware for API routes.

```typescript
// app/layout.tsx or a central init file
import { initSilker } from '@silker-ai/agent';

initSilker({
  apiKey: process.env.SILKER_API_KEY!,
  appId: 'my-nextjs-app',
  features: {
    xssDetection: true,
    promptInjectionDetection: true
  }
});
```

### Express.js
Drop Silker into your middleware stack for instant protection.

```typescript
import express from 'express';
import { middleware } from '@silker-ai/agent';

const app = express();

app.use(middleware({
  apiKey: process.env.SILKER_API_KEY!,
  appId: 'my-express-api'
}));
```

### Generic Node.js / Serverless
Protect any Node.js process (scripts, cron jobs, background tasks).

```typescript
import SilkerAI from '@silker-ai/agent';

await SilkerAI.init({ apiKey: 'your_sk_key' });

// All outgoing fetch() calls are now monitored for data leaks and anomalies.
const response = await fetch('https://api.external.com/data');
```

---

## 🛠 Features

### 🛡️ Core Security
- **SQL Injection (SQLi)**: Advanced heuristic analysis of queries and payloads.
- **Cross-Site Scripting (XSS)**: Deep inspection of HTML entities and obfuscated scripts.
- **Path Traversal**: Prevents unauthorized access to local files (`../etc/passwd`).
- **Rate Limiting & IP Banning**: Protects against brute-force and DoS.

### 🧠 AI & LLM Protection
- **Prompt Injection Detection**: Blocks "jailbreaks" and "ignore previous instructions" attacks.
- **Input/Output Monitoring**: Scans both prompts sent to LLMs and their responses.

### 🔐 Advanced Detection
- **Data Leakage (DLP)**: Detects API keys, Credit Card numbers, SSNs, and Secrets in transit.
- **SSRF & CSRF Prevention**: Blocks forged requests to internal and external networks.
- **IDOR Detection**: Identifies unauthorized object reference manipulation.
- **Host Header Injection**: Prevents cache poisoning and password reset attacks.

---

## 🌐 Dashboard & Telemetry

Silker AI connects to a real-time dashboard for threat visibility.

- **Intelligent Flush**: In environments like Vercel, the agent ensures all security events are successfully sent before the process terminates.
- **Performance Insights**: Monitor response times and find slow endpoints automatically.
- **Audit Logs**: Keep a tamper-proof record of every blocked attempt for compliance (GDPR/HIPAA).

---

## 💻 Compatibility

| Environment | Status | Notes |
| :--- | :--- | :--- |
| **Node.js** | ✅ Supported | Version 14.x and higher. |
| **Next.js** | ✅ Supported | API Routes, Middleware, Server Actions. |
| **Vercel / Lambda**| ✅ Optimized | Specialized "Serverless Flush" mechanism. |
| **Express / NestJS**| ✅ Supported | Via standard middleware. |
| **Bun / Deno** | ⚠️ Experimental | Core features work; full testing in progress. |

---

## 📖 Documentation

For detailed configuration options, see our [Configuration Guide](./CONFIGURATION.md) or visit [docs.silkerai.com](https://silkerai.com/docs).

---

## ⚖️ License

Proprietary Software. All rights reserved. For commercial inquiries, contact [sales@silkerai.com](mailto:sales@silkerai.com).

---
**Silker AI** - Runtime Security for the AI Era.
