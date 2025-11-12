# @silker/ai-sdk

**Lekki Agent Bezpieczeństwa Runtime** dla aplikacji opartych na AI. Wykrywa anomalie, blokuje ataki i zapewnia ochronę w czasie rzeczywistym z inteligentnymi informacjami.

Doskonale nadaje się dla Cursor, Bubble, Next.js na Vercel i każdej aplikacji Node.js, która potrzebuje bezpieczeństwa runtime bez dużego nakładu pracy.

## ✨ Funkcje

### Podstawowe Zabezpieczenia
- 🚦 **Wykrywanie Ograniczeń Częstotliwości** - Blokuje próby brute-force (>5 żądań/min na IP)
- 🛡️ **Sprawdzanie Poprawności Payload** - Wykrywa SQLi, XSS i szkodliwe wzorce
- 🔒 **Path Traversal Protection** - Zapobiega przechodzeniu katalogów (`../`)
- 🎯 **Wykrywanie Anomalii** - Niestandardowe reguły dla podejrzanych aktywności

### Ochrona OWASP Top 10
- 🛡️ **CSRF Protection** - Wykrywa brakujące tokeny CSRF
- 🌐 **SSRF Prevention** - Blokuje żądania do sieci wewnętrznych i metadanych chmury
- 🔐 **IDOR Detection** - Identyfikuje ataki insecure direct object reference
- 📋 **Host Header Injection Protection** - Zapobiega manipulacji nagłówkiem hosta
- 🔒 **Security Headers Validation** - Waliduje obecność nagłówków bezpieczeństwa

### Zaawansowane Funkcje Bezpieczeństwa
- 🔍 **Zapobieganie Wyciekom Danych** - Skanuje pod kątem kluczy API, PII i sekretów
- 🤖 **Analiza Zachowań Użytkowników** - Wykrywanie botów i anomalii sesji
- 📊 **Walidacja Schematów API** - Sprawdza strukturę API i zgodność z OpenAPI
- 📁 **Bezpieczeństwo Uploadów Plików** - Skanowanie malware i walidacja typów plików
- 🔗 **Bezpieczeństwo Integracji Zewnętrznych** - Monitoruje wywołania API i webhooki
- ⚖️ **Monitorowanie Zgodności** - GDPR, HIPAA i ochrona danych
- 🕵️ **Wywiad Zagrożeń** - Blokowanie na podstawie feeds zagrożeń
- 🔐 **Weryfikacja Zero-trust** - Ciągła weryfikacja wszystkich operacji

### Monitorowanie i Analityka
- ⚡ **Monitorowanie Wydajności** - Wykrywa anomalie wydajności i wolne endpointy
- 📝 **Zaawansowane Logowanie Audit** - Kompleksowe logowanie zdarzeń bezpieczeństwa
- ⚙️ **Zarządzanie Konfiguracją Runtime** - Aktualizacje konfiguracji w czasie rzeczywistym
- 💚 **Sprawdzanie Zdrowia Systemu** - Monitorowanie zdrowia agenta i autodiagnostyka

### Integracja i Wdrożenie
- ☁️ **Integracja z Chmurą** - Alerty w czasie rzeczywistym do Cloudflare Workers + Grok AI
- 🌐 **Tryb Proxy** - Wsparcie dla konfiguracji CNAME dla zaawansowanych wdrożeń
- 🎣 **Auto-Haki** - Bezproblemowa integracja z fetch, Express i niestandardowymi workflow
- 🔒 **Sanityzacja Danych** - Automatyczne maskowanie wrażliwych danych przed wysłaniem
- ⚡ **Samowystarczalny** - ~63KB spakowane gzip, wszystkie zależności włączone

## Instalacja

```bash
npm install @silker/ai-sdk
```

## Kompatybilność

Silker AI SDK działa z **dowolnym runtime Node.js** (po stronie serwera):

### Pełne Wsparcie

- **Node.js** (v14+) - Wszystkie funkcje działają
- **Next.js** (Server-side / API Routes) - Pełne wsparcie przez `SilkerAI.init()` i `middleware()`
- **Express.js** - Pełne wsparcie przez `middleware()`
- **Fastify** - Działa z adapterem Express middleware
- **Koa.js** - Działa z adapterem Express middleware
- **NestJS** - Działa jako Express middleware
- **SvelteKit** - Server-side API routes
- **Remix** - Server-side loaders/actions
- **Nuxt.js** - Server-side API routes
- **Cloudflare Workers** - Ograniczone (brak `process.env`, użyj parametru `env`)
- **Vercel Edge Functions** - Ograniczone (brak `process.env`, użyj parametru `env`)
- **AWS Lambda** - Pełne wsparcie
- **Google Cloud Functions** - Pełne wsparcie
- **Azure Functions** - Pełne wsparcie

### Ograniczone Wsparcie

- **Przeglądarka/Client-side** - Tylko `hookFetch()` działa, brak `process.env`, brak health checks
- **Deno** - Nie testowane, może wymagać modyfikacji
- **Bun** - Powinno działać, ale nie oficjalnie testowane

### Wymagania

- **Node.js**: >= 14.0.0
- **Runtime**: Server-side środowisko Node.js
- **Zależności**: axios, events, http-proxy (wbudowane)

### Przykłady dla Różnych Frameworków

#### Next.js (App Router)

```typescript
// app/api/route.ts lub middleware.ts
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
// pages/_middleware.ts lub pages/api/[...route].ts
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

#### Cloudflare Workers / Vercel Edge

```typescript
// Uwaga: Użyj parametru env zamiast process.env
import SilkerAI from '@silker/ai-sdk';

export default {
  async fetch(request: Request, env: any) {
    await SilkerAI.init({
      apiKey: env.SILKER_API_KEY,
      features: { cloudCommunication: true }
    });
    
    // Twoja logika worker...
  }
};
```

## Szybki Start

### Podstawowa Konfiguracja

```typescript
import SilkerAI from '@silker/ai-sdk';

// Zainicjalizuj z kluczem API ze zmiennej środowiskowej
await SilkerAI.init({
  apiKey: process.env.SILKER_API_KEY!,
  debug: true // Opcjonalne: Włącz logowanie debug
});

// To wszystko! Twoja aplikacja jest teraz chroniona
// Wywołania API przez fetch() są automatycznie monitorowane
```

**Uwaga Bezpieczeństwa**: Nigdy nie hardcoduj kluczy API w kodzie. Zawsze używaj zmiennych środowiskowych:
```bash
export SILKER_API_KEY="your-api-key-here"
```

### Integracja z Express.js

```typescript
import express from 'express';
import SilkerAI from '@silker/ai-sdk';

const app = express();

const options = { apiKey: process.env.SILKER_API_KEY! };

await SilkerAI.init(options);

// Dodaj middleware dla monitorowania specyficznego dla Express
app.use(SilkerAI.middleware(options));

app.post('/api/login', (req, res) => {
  // Silker AI automatycznie skanuje żądania
  res.json({ success: true });
});
```

### Monitorowanie Niestandardowych Workflow

```typescript
import SilkerAI from '@silker/ai-sdk';

// Monitoruj niestandardową logikę biznesową
function processPayment(amount: number, userId: string) {
  SilkerAI.emitWorkflowEvent({
    method: 'POST',
    url: `/payments/${userId}`,
    payload: { amount },
    ip: 'user-ip-here'
  });

  // Twoja logika płatności...
}
```

### Tryb Proxy (Zaawansowany)

Dla konfiguracji CNAME lub gdy potrzebujesz proxy ruchu przez Silker AI:

```bash
# Ustaw zmienne środowiskowe
export SILKER_TARGET_URL="http://your-app.com"
export SILKER_PROXY_PORT="8080"

# Włącz tryb proxy
await SilkerAI.init({
  apiKey: process.env.SILKER_API_KEY!,
  proxyMode: true
});
```

Następnie skieruj swoją domenę na `http://localhost:8080` a Silker AI będzie proxy wszystkie żądania ze skanowaniem bezpieczeństwa.

### Monitorowanie Wydajności

```typescript
import SilkerAI from '@silker/ai-sdk';

// Zapisuj metryki wydajności
SilkerAI.recordPerformanceMetrics(event, responseTime, statusCode);

// Pobierz raport wydajności
const report = SilkerAI.getPerformanceReport();
console.log('Średni czas odpowiedzi:', report.summary.averageResponseTime);
console.log('Wolne żądania:', report.summary.slowRequests);
console.log('Anomalie:', report.anomalies);
```

### Logowanie Audytu

```typescript
import SilkerAI from '@silker/ai-sdk';

// Loguj zdarzenie audytu
SilkerAI.logAuditEvent(event, 'blocked', 'SQL injection detected', 'high');

// Pobierz wpisy audytu z filtrami
const criticalLogs = SilkerAI.getAuditLogs(50, 'critical', 'blocked');

// Pobierz podsumowanie audytu
const summary = SilkerAI.getAuditSummary();
console.log('Całkowita liczba wpisów:', summary.totalLogs);
console.log('Podział według ważności:', summary.severityBreakdown);
```

### Zarządzanie Konfiguracją Runtime

```typescript
import SilkerAI from '@silker/ai-sdk';

// Pobierz aktualną konfigurację
const config = SilkerAI.getRuntimeConfig();
console.log('Próg limitu szybkości:', config.rateLimitThreshold);

// Zaktualizuj konfigurację w czasie rzeczywistym
const result = SilkerAI.updateRuntimeConfig({
  rateLimitThreshold: 10,
  slowRequestThreshold: 3000,
  debug: true
});
console.log('Zaktualizowane klucze:', result.updated);
```

### Sprawdzanie Zdrowia Systemu

```typescript
import SilkerAI from '@silker/ai-sdk';

// Wykonaj sprawdzenie zdrowia
const health = SilkerAI.performHealthCheck();
console.log('Status:', health.status); // 'healthy' | 'degraded' | 'unhealthy'
console.log('Pamięć:', health.checks.memory.usage, 'MB');
console.log('Czas działania:', health.uptime, 'ms');
```

### Analiza Zachowań Użytkowników

```typescript
import SilkerAI from '@silker/ai-sdk';

// Analizuj zachowanie użytkownika
const behavior = SilkerAI.analyzeUserBehavior(event);
if (behavior.isAnomalous) {
  console.log('Wykryto anomalie:', behavior.reasons);
  console.log('Wynik punktowy:', behavior.score);
}
```

### Walidacja API

```typescript
import SilkerAI from '@silker/ai-sdk';

// Waliduj schemat API
const apiValidation = SilkerAI.performApiValidation(event);
if (!apiValidation.valid) {
  console.log('Ostrzeżenia API:', apiValidation.warnings);
}

// Waliduj nagłówki bezpieczeństwa
const headerValidation = SilkerAI.validateSecurityHeaders(req.headers);
if (!headerValidation.valid) {
  console.log('Brakujące nagłówki:', headerValidation.missing);
}
```

## Opcje Konfiguracji

```typescript
interface SilkerOptions {
  apiKey: string;          // Wymagane: Twój klucz API Silker AI
  endpoint?: string;       // Opcjonalne: Niestandardowy endpoint chmurowy (domyślnie: Cloudflare Workers)
  debug?: boolean;         // Opcjonalne: Włącz logowanie do konsoli
  proxyMode?: boolean;     // Opcjonalne: Włącz tryb proxy dla konfiguracji CNAME
  features?: SilkerFeatures; // Opcjonalne: Włącz/wyłącz konkretne funkcjonalności
}

interface SilkerFeatures {
  rateLimit?: boolean;                      // Wykrywanie limitu szybkości
  sqliDetection?: boolean;                 // Wykrywanie ataków SQL injection
  xssDetection?: boolean;                  // Wykrywanie ataków XSS
  pathTraversalDetection?: boolean;        // Ochrona przed path traversal
  csrfDetection?: boolean;                 // Ochrona CSRF
  ssrfDetection?: boolean;                 // Zapobieganie SSRF
  idorDetection?: boolean;                 // Wykrywanie IDOR
  hostHeaderInjectionDetection?: boolean;  // Ochrona przed host header injection
  securityHeadersValidation?: boolean;    // Walidacja nagłówków bezpieczeństwa
  dataLeakageDetection?: boolean;         // Zapobieganie wyciekom danych
  apiSchemaValidation?: boolean;           // Walidacja schematu API
  sessionAnomaliesDetection?: boolean;    // Wykrywanie anomalii sesji
  fileUploadDetection?: boolean;          // Bezpieczeństwo uploadów plików
  thirdPartyDetection?: boolean;          // Bezpieczeństwo integracji zewnętrznych
  complianceDetection?: boolean;          // Monitorowanie compliance
  threatIntelligence?: boolean;           // Threat intelligence
  zeroTrustDetection?: boolean;           // Weryfikacja zero-trust
  auditLogging?: boolean;                  // Logowanie audytu
  performanceMonitoring?: boolean;       // Monitorowanie wydajności
  cloudCommunication?: boolean;          // Komunikacja z chmurą
}
```

### Przykład Włączania/Wyłączania Funkcjonalności

Możesz włączyć lub wyłączyć konkretne funkcjonalności bezpieczeństwa:

```typescript
import SilkerAI from '@silker/ai-sdk';

await SilkerAI.init({
  apiKey: process.env.SILKER_API_KEY!,
  features: {
    rateLimit: true,              // Włącz wykrywanie limitu szybkości
    sqliDetection: true,          // Włącz wykrywanie SQL injection
    xssDetection: false,          // Wyłącz wykrywanie XSS
    auditLogging: true,           // Włącz logowanie audytu
    cloudCommunication: true     // Włącz komunikację z chmurą
  }
});
```

Domyślnie wszystkie funkcjonalności są **włączone** (zachowana kompatybilność wsteczna). Ustaw funkcjonalność na `false`, aby ją wyłączyć.

**Najlepsze Praktyki Bezpieczeństwa:**
- Zawsze używaj zmiennych środowiskowych dla kluczy API: `process.env.SILKER_API_KEY`
- Nigdy nie commituj kluczy API do kontroli wersji
- Używaj plików `.env` (dodaj do `.gitignore`) do lokalnego rozwoju
- Używaj bezpiecznego zarządzania sekretami w produkcji (AWS Secrets Manager, Vercel Environment Variables, itp.)

## Funkcje Bezpieczeństwa

### Rdzeń Silnika Bezpieczeństwa
- **Ograniczenia Częstotliwości**: Blokuje IP przekraczające 5 żądań na minutę
- **SQL Injection**: Wykrywa popularne wzorce SQLi w payload
- **Ataki XSS**: Skanuje pod kątem prób wstrzyknięcia skryptów
- **Path Traversal**: Zapobiega przechodzeniu katalogów `../`
- **Podejrzane IP**: Oznacza nietypowe wzorce ruchu

### Ochrona OWASP Top 10
- **Ochrona CSRF**: Wykrywa brakujące tokeny CSRF w żądaniach zmieniających stan
- **Zapobieganie SSRF**: Blokuje żądania do wewnętrznych/sieci prywatnych i metadanych chmury
- **Wykrywanie IDOR**: Identyfikuje ataki typu insecure direct object references
- **Host Header Injection**: Zapobiega manipulacji nagłówkiem hosta
- **Nagłówki Bezpieczeństwa**: Waliduje obecność podstawowych nagłówków bezpieczeństwa

### Zaawansowane Funkcje Bezpieczeństwa
- **Zapobieganie Wyciekom Danych**: Skanuje pod kątem kluczy API, PII i wrażliwych danych
  - Wykrywanie kluczy API w payloadach i odpowiedziach
  - Skanowanie pod kątem danych osobowych (SSN, numery kart, emaile)
  - Wykrywanie sekretów i tokenów
  - Identyfikacja danych dostępowych do baz danych
- **Analiza Zachowań Użytkowników**: Wykrywanie botów i anomalii sesji
  - Wykrywanie botów na podstawie regularności żądań
  - Analiza odstępów czasowych między żądaniami
  - Wykrywanie podejrzanych kombinacji metod HTTP
  - Identyfikacja nadmiernego dostępu do endpointów API
  - Analiza długości sesji i aktywności
- **Walidacja Schematów API**: Sprawdza strukturę API i zgodność z OpenAPI
  - Walidacja wymaganych pól dla endpointów użytkownika/konta
  - Sprawdzanie formatu emaili
  - Walidacja struktury odpowiedzi API
  - Zgodność z konwencjami OpenAPI
  - Walidacja parametrów URL i query strings
- **Bezpieczeństwo Uploadów Plików**: Skanowanie malware i walidacja typów plików
  - Sprawdzanie magic bytes (sygnatur plików)
  - Walidacja typów MIME
  - Wykrywanie plików wykonywalnych
  - Sprawdzanie rozmiaru plików (max 10MB)
  - Wykrywanie niebezpiecznych nazw plików
  - Ochrona przed path traversal w nazwach plików
- **Bezpieczeństwo Integracji Zewnętrznych**: Monitoruje zewnętrzne wywołania API i webhooki
  - Wykrywanie podejrzanych domen (pastebin, transfer.sh, ngrok)
  - Walidacja webhooków i callbacków
  - Wykrywanie ekspozycji kluczy API w żądaniach zewnętrznych
  - Monitorowanie dużych payloadów w żądaniach zewnętrznych
  - Wykrywanie wrażliwych danych w integracjach
- **Monitorowanie Zgodności**: GDPR, HIPAA i ochrona danych
  - Wykrywanie przetwarzania PII bez zgody GDPR
  - Weryfikacja polityk retencji danych
  - Wykrywanie danych medycznych bez autoryzacji HIPAA
  - Wymaganie szyfrowania TLS dla danych zdrowotnych
  - Klasyfikacja danych wrażliwych
- **Wywiad Zagrożeń**: Blokowanie w czasie rzeczywistym na podstawie feeds zagrożeń
  - Baza znanych zagrożonych IP
  - Lista złośliwych domen
  - Wykrywanie skanerów bezpieczeństwa (sqlmap, nikto, dirbuster)
  - Identyfikacja podejrzanych user-agentów
- **Weryfikacja Zero-trust**: Ciągła weryfikacja wszystkich operacji
  - Wymaganie autentykacji dla wszystkich żądań
  - Weryfikacja pochodzenia żądań (Origin/Referer)
  - Weryfikacja urządzenia (User-Agent)
  - Dodatkowe potwierdzenia dla operacji destrukcyjnych (DELETE)
  - Weryfikacja dostępu poza godzinami pracy

### Funkcje Monitorowania Enterprise
- **Monitorowanie Wydajności**: Wykrywa anomalie wydajności i wolne endpointy
  - Śledzenie czasu odpowiedzi dla każdego endpointu
  - Wykrywanie wolnych żądań (>5s)
  - Analiza średniego czasu odpowiedzi
  - Identyfikacja wolnych endpointów (>3s średnio)
- **Zaawansowane Logowanie Audit**: Kompleksowe logowanie zdarzeń bezpieczeństwa dla zgodności
  - Logowanie wszystkich akcji (allowed, blocked, flagged)
  - Poziomy ważności (low, medium, high, critical)
  - Filtrowanie i wyszukiwanie wpisów
  - Podsumowania statystyczne
- **API Zarządzania Konfiguracją**: Aktualizacje konfiguracji w czasie rzeczywistym
  - Dynamiczna zmiana progów limitu szybkości
  - Konfiguracja progów wolnych żądań
  - Włączanie/wyłączanie funkcji monitorowania
  - Niestandardowe reguły bezpieczeństwa
- **Sprawdzanie Zdrowia**: Monitorowanie zdrowia agenta i autodiagnostyka
  - Status pamięci (użycie heap)
  - Status wydajności (średni czas odpowiedzi)
  - Status bezpieczeństwa (ostatnie blokady)
  - Status łączności z chmurą
  - Czas działania systemu (uptime)

### Obsługa Odpowiedzi

Gdy anomalie są wykrywane:

1. **Blokuj Żądanie**: Zwraca 403 Forbidden z ID alertu
2. **Alert Chmurowy**: Wysyła metadane do Twojego backendu dla analizy AI
3. **Łagodna Degradacja**: Nigdy nie psuje Twojej aplikacji - zawodzi bezpiecznie

## Integracja z Chmurą

Silker AI komunikuje się z Twoim backendem Cloudflare Workers:

```typescript
// Przykładowa odpowiedź chmurowa
{
  block: true,           // Czy zablokować żądanie
  fixSnippet?: string,   // Sugestia naprawy wygenerowana przez AI
  severity: 'high',      // low | medium | high
  alertId: 'alert-123'   // Unikalny identyfikator alertu
}
```

### Sanityzacja Danych

Silker AI automatycznie sanityzuje wrażliwe dane przed wysłaniem do chmury:
- Hasła i sekrety są maskowane
- Tokeny i klucze API są ukrywane
- Dane osobowe są chronione
- Connection strings do baz danych są maskowane

## API Reference

### Eksportowane Funkcje

```typescript
// Inicjalizacja
SilkerAI.init(options: SilkerOptions): Promise<void>
SilkerAI.emitWorkflowEvent(event: Omit<SilkerEvent, 'timestamp'>): void

// Middleware Express
SilkerAI.middleware(options: SilkerOptions): (req, res, next) => Promise<void>

// Monitorowanie wydajności
SilkerAI.recordPerformanceMetrics(event: SilkerEvent, responseTime: number, statusCode?: number): void
SilkerAI.getPerformanceReport(): PerformanceReport

// Audyt
SilkerAI.logAuditEvent(event: SilkerEvent, action: 'allowed' | 'blocked' | 'flagged', reason: string, severity?: 'low' | 'medium' | 'high' | 'critical', metadata?: any): void
SilkerAI.getAuditLogs(limit?: number, severity?: string, action?: string): AuditLogEntry[]
SilkerAI.getAuditSummary(): AuditSummary

// Konfiguracja
SilkerAI.getRuntimeConfig(): RuntimeConfig
SilkerAI.updateRuntimeConfig(updates: Partial<RuntimeConfig>): { success: boolean; updated: string[] }

// Health check
SilkerAI.performHealthCheck(): HealthStatus

// Komunikacja z chmurą
SilkerAI.sendToCloud(event: SilkerEvent, options: SilkerOptions): Promise<CloudResponse | null>
```

### Typy

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

## Testowanie

```bash
npm test
```

Testy obejmują:
- Inicjalizację agenta
- Wykrywanie anomalii (ograniczenia częstotliwości, SQLi, XSS)
- Komunikację z chmurą
- Obsługę błędów

## Build i Publikacja

```bash
npm run build    # Kompiluj TypeScript + bundle z esbuild
npm test         # Uruchom suite testów
npm publish      # Opublikuj w rejestrze npm
```

## Architektura

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Twoja App     │───▶│   Silker AI      │───▶│ Cloudflare + AI │
│                 │    │                  │    │                 │
│ • wywołania     │    │ • Wykrywanie     │    │ • W czasie      │
│   fetch()       │    │   Anomalii       │    │   rzeczywistym  │
│ • trasy API     │    │ • Ograniczenia   │    │ • Analiza AI    │
│ • Workflow      │    │   Częstotliwości │    │ • Alerty        │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Współpraca

Silker AI jest zbudowany dla społeczności deweloperów. PR-y mile widziane!

## Licencja

Licencja MIT

---

**Stworzone przez Silker AI**
