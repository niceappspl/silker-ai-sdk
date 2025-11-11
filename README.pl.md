# @vibeguard/agent

🛡️ **Lekki Agent Bezpieczeństwa Runtime** dla aplikacji vibe-coding/no-code. Wykrywa anomalie, blokuje ataki i wysyła alerty do Twojej chmurowej infrastruktury z wsparciem AI.

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

## 🚀 Instalacja

```bash
npm install @vibeguard/agent
```

## 🏁 Szybki Start

### Podstawowa Konfiguracja

```typescript
import { initVibeGuard } from '@vibeguard/agent';

// Zainicjalizuj z swoim kluczem API
await initVibeGuard({
  apiKey: 'your-api-key-here',
  debug: true // Opcjonalne: Włącz logowanie debug
});

// To wszystko! Twoja aplikacja jest teraz chroniona ✨
// Wywołania API przez fetch() są automatycznie monitorowane
```

### Integracja z Express.js

```typescript
import express from 'express';
import { initVibeGuard, middleware } from '@vibeguard/agent';

const app = express();

await initVibeGuard({ apiKey: 'your-api-key' });

// Dodaj middleware dla monitorowania specyficznego dla Express
app.use(middleware({ apiKey: 'your-api-key' }));

app.post('/api/login', (req, res) => {
  // VibeGuard automatycznie skanuje żądania
  res.json({ success: true });
});
```

### Monitorowanie Niestandardowych Workflow

```typescript
import { emitWorkflowEvent } from '@vibeguard/agent';

// Monitoruj niestandardową logikę biznesową
function processPayment(amount: number, userId: string) {
  emitWorkflowEvent({
    method: 'POST',
    url: `/payments/${userId}`,
    payload: { amount },
    ip: 'user-ip-here'
  });

  // Twoja logika płatności...
}
```

### Tryb Proxy (Zaawansowany)

Dla konfiguracji CNAME lub gdy potrzebujesz proxy ruchu przez VibeGuard:

```bash
# Ustaw zmienne środowiskowe
export VIBEGUARD_TARGET_URL="http://your-app.com"
export VIBEGUARD_PROXY_PORT="8080"

# Włącz tryb proxy
await initVibeGuard({
  apiKey: 'your-api-key',
  proxyMode: true
});
```

Następnie skieruj swoją domenę na `http://localhost:8080` a VibeGuard będzie proxy wszystkie żądania ze skanowaniem bezpieczeństwa.

### Monitorowanie Wydajności

```typescript
import { recordPerformanceMetrics, getPerformanceReport } from '@vibeguard/agent';

// Zapisuj metryki wydajności
recordPerformanceMetrics(event, responseTime, statusCode);

// Pobierz raport wydajności
const report = getPerformanceReport();
console.log('Średni czas odpowiedzi:', report.summary.averageResponseTime);
console.log('Wolne żądania:', report.summary.slowRequests);
console.log('Anomalie:', report.anomalies);
```

### Logowanie Audytu

```typescript
import { logAuditEvent, getAuditLogs, getAuditSummary } from '@vibeguard/agent';

// Loguj zdarzenie audytu
logAuditEvent(event, 'blocked', 'SQL injection detected', 'high');

// Pobierz wpisy audytu z filtrami
const criticalLogs = getAuditLogs(50, 'critical', 'blocked');

// Pobierz podsumowanie audytu
const summary = getAuditSummary();
console.log('Całkowita liczba wpisów:', summary.totalLogs);
console.log('Podział według ważności:', summary.severityBreakdown);
```

### Zarządzanie Konfiguracją Runtime

```typescript
import { getRuntimeConfig, updateRuntimeConfig } from '@vibeguard/agent';

// Pobierz aktualną konfigurację
const config = getRuntimeConfig();
console.log('Próg limitu szybkości:', config.rateLimitThreshold);

// Zaktualizuj konfigurację w czasie rzeczywistym
const result = updateRuntimeConfig({
  rateLimitThreshold: 10,
  slowRequestThreshold: 3000,
  debug: true
});
console.log('Zaktualizowane klucze:', result.updated);
```

### Sprawdzanie Zdrowia Systemu

```typescript
import { performHealthCheck } from '@vibeguard/agent';

// Wykonaj sprawdzenie zdrowia
const health = performHealthCheck();
console.log('Status:', health.status); // 'healthy' | 'degraded' | 'unhealthy'
console.log('Pamięć:', health.checks.memory.usage, 'MB');
console.log('Czas działania:', health.uptime, 'ms');
```

### Analiza Zachowań Użytkowników

```typescript
import { analyzeUserBehavior } from '@vibeguard/agent';

// Analizuj zachowanie użytkownika
const behavior = analyzeUserBehavior(event);
if (behavior.isAnomalous) {
  console.log('Wykryto anomalie:', behavior.reasons);
  console.log('Wynik punktowy:', behavior.score);
}
```

### Walidacja API

```typescript
import { performApiValidation, validateSecurityHeaders } from '@vibeguard/agent';

// Waliduj schemat API
const apiValidation = performApiValidation(event);
if (!apiValidation.valid) {
  console.log('Ostrzeżenia API:', apiValidation.warnings);
}

// Waliduj nagłówki bezpieczeństwa
const headerValidation = validateSecurityHeaders(req.headers);
if (!headerValidation.valid) {
  console.log('Brakujące nagłówki:', headerValidation.missing);
}
```

## 🔧 Opcje Konfiguracji

```typescript
interface VibeGuardOptions {
  apiKey: string;          // Wymagane: Twój klucz API VibeGuard
  endpoint?: string;       // Opcjonalne: Niestandardowy endpoint chmurowy (domyślnie: Cloudflare Workers)
  debug?: boolean;         // Opcjonalne: Włącz logowanie do konsoli
  proxyMode?: boolean;     // Opcjonalne: Włącz tryb proxy dla konfiguracji CNAME
}
```

## 🛡️ Funkcje Bezpieczeństwa

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

## 📡 Integracja z Chmurą

VibeGuard komunikuje się z Twoim backendem Cloudflare Workers:

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

VibeGuard automatycznie sanityzuje wrażliwe dane przed wysłaniem do chmury:
- Hasła i sekrety są maskowane
- Tokeny i klucze API są ukrywane
- Dane osobowe są chronione
- Connection strings do baz danych są maskowane

## 📚 API Reference

### Eksportowane Funkcje

```typescript
// Inicjalizacja
initVibeGuard(options: VibeGuardOptions): Promise<void>
emitWorkflowEvent(event: Omit<VibeGuardEvent, 'timestamp'>): void

// Middleware Express
middleware(options: VibeGuardOptions): (req, res, next) => Promise<void>

// Monitorowanie wydajności
recordPerformanceMetrics(event: VibeGuardEvent, responseTime: number, statusCode?: number): void
getPerformanceReport(): PerformanceReport

// Audyt
logAuditEvent(event: VibeGuardEvent, action: 'allowed' | 'blocked' | 'flagged', reason: string, severity?: 'low' | 'medium' | 'high' | 'critical', metadata?: any): void
getAuditLogs(limit?: number, severity?: string, action?: string): AuditLogEntry[]
getAuditSummary(): AuditSummary

// Konfiguracja
getRuntimeConfig(): RuntimeConfig
updateRuntimeConfig(updates: Partial<RuntimeConfig>): { success: boolean; updated: string[] }

// Health check
performHealthCheck(): HealthStatus

// Komunikacja z chmurą
sendToCloud(event: VibeGuardEvent, options: VibeGuardOptions): Promise<CloudResponse | null>
```

### Typy

```typescript
interface VibeGuardOptions {
  apiKey: string;
  endpoint?: string;
  debug?: boolean;
  proxyMode?: boolean;
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

## 🧪 Testowanie

```bash
npm test
```

Testy obejmują:
- ✅ Inicjalizację agenta
- ✅ Wykrywanie anomalii (ograniczenia częstotliwości, SQLi, XSS)
- ✅ Komunikację z chmurą
- ✅ Obsługę błędów

## 📦 Build i Publikacja

```bash
npm run build    # Kompiluj TypeScript + bundle z esbuild
npm test         # Uruchom suite testów
npm publish      # Opublikuj w rejestrze npm
```

## 🎯 Architektura

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Twoja App     │───▶│  VibeGuard Agent │───▶│ Cloudflare + AI │
│                 │    │                  │    │                 │
│ • wywołania     │    │ • Wykrywanie     │    │ • W czasie      │
│   fetch()       │    │   Anomalii       │    │   rzeczywistym  │
│ • trasy API     │    │ • Ograniczenia   │    │ • Analiza AI    │
│ • Workflow      │    │   Częstotliwości │    │ • Alerty        │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🤝 Współpraca

VibeGuard jest zbudowany z ❤️ dla społeczności deweloperów. PR-y mile widziane!

## 📄 Licencja

Licencja MIT - Trzymaj vibe bezpiecznie! 🎉

---

**Stworzone z ❤️ przez VibeGuard AI - Bezpieczeństwo, które nie wkurza**
