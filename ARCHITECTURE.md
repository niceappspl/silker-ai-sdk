# Silker AI Multi-Language SDK Architecture

## Obecna Architektura (Node.js SDK)

```
┌─────────────────────────────────────────────────────────────┐
│                    Node.js Application                      │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │  Express.js  │  │  fetch() API  │  │  Custom       │   │
│  │  Middleware  │  │  Hook         │  │  Workflows    │   │
│  └──────┬───────┘  └──────┬────────┘  └──────┬────────┘   │
│         │                 │                    │             │
│         └─────────────────┼────────────────────┘             │
│                           │                                  │
│                  ┌────────▼────────┐                        │
│                  │   Silker AI     │                        │
│                  │  (TypeScript)   │                        │
│                  └────────┬─────────┘                        │
│                           │                                  │
│         ┌─────────────────┼─────────────────┐               │
│         │                 │                 │                │
│  ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐        │
│  │  Local      │  │  Cloud      │  │  Analytics  │        │
│  │  Detection  │  │  Comm       │  │  & Audit    │        │
│  │  Engine     │  │  (REST API) │  │             │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  Cloud Backend  │
                  │  (Cloudflare +  │
                  │   Grok AI)      │
                  └─────────────────┘
```

## Architektura Multi-Language SDK

### Strategia: Wspólny Protokół + Nativne Implementacje

```
┌─────────────────────────────────────────────────────────────┐
│              Wspólny Protokół Komunikacji                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  REST API Contract                                   │  │
│  │  POST /api                                           │  │
│  │  Headers: Authorization, X-Silker-Version           │  │
│  │  Body: SilkerEvent (JSON)                           │  │
│  │  Response: CloudResponse (JSON)                     │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Wspólne Definicje Reguł Detekcji                    │  │
│  │  - SQLi patterns                                     │  │
│  │  - XSS patterns                                       │  │
│  │  - Rate limiting logic                                │  │
│  │  - OWASP Top 10 rules                                 │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Node.js SDK  │  │  Python SDK  │  │   Java SDK   │
│ (obecny)     │  │  (przyszły)  │  │  (przyszły)  │
└──────────────┘  └──────────────┘  └──────────────┘
```

## Komponenty do Współdzielenia

### 1. Protokół Komunikacji z Chmurą (REST API)

**Endpoint:** `POST https://silker.cloudflareworkers.com/api`

**Request:**
```json
{
  "method": "GET|POST|PUT|DELETE|...",
  "url": "/api/users/123",
  "payload": "sanitized_string_or_object",
  "ip": "192.168.1.1",
  "timestamp": 1234567890,
  "userAgent": "Mozilla/5.0...",
  "headers": {
    "content-type": "application/json",
    "authorization": "Bearer ***MASKED***"
  }
}
```

**Response:**
```json
{
  "block": true,
  "fixSnippet": "Suggested fix code",
  "severity": "high",
  "alertId": "alert-123"
}
```

**Headers:**
- `Authorization: Bearer {apiKey}`
- `Content-Type: application/json`
- `X-Silker-Version: {version}`

### 2. Wspólne Reguły Detekcji

Reguły można współdzielić przez:
- **JSON/YAML config files** - definicje wzorców
- **Shared library** - jeśli użyjemy WebAssembly
- **Documentation** - specyfikacja reguł dla każdego SDK

**Przykład struktury reguł:**
```yaml
# rules.yaml
sqli_patterns:
  - pattern: "/(\\bUNION\\b|\\bSELECT\\b|\\bINSERT\\b)/i"
    description: "SQL UNION/SELECT injection"
    
xss_patterns:
  - pattern: "/<script[^>]*>.*?<\\/script>/i"
    description: "Script tag injection"
    
rate_limit:
  window_ms: 60000
  max_requests: 5
```

### 3. Sanityzacja Danych

Wspólna logika maskowania wrażliwych danych przed wysłaniem do chmury.

## Implementacja dla Różnych Języków

### Python SDK

```python
# silker/__init__.py
from silker.agent import SilkerAI

agent = SilkerAI(api_key="your-key")
agent.init()

# Flask integration
from silker.flask import SilkerMiddleware

app = Flask(__name__)
app.wsgi_app = SilkerMiddleware(app.wsgi_app, api_key="your-key")

# Django integration
MIDDLEWARE = [
    'silker.django.SilkerMiddleware',
]

# FastAPI integration
from silker.fastapi import SilkerMiddleware

app.add_middleware(SilkerMiddleware, api_key="your-key")
```

**Struktura:**
```
silker-python/
├── silker/
│   ├── __init__.py
│   ├── agent.py          # Główna klasa agenta
│   ├── detection.py      # Lokalna detekcja anomalii
│   ├── cloud.py          # Komunikacja z chmurą
│   ├── sanitization.py   # Sanityzacja danych
│   ├── flask.py          # Flask middleware
│   ├── django.py         # Django middleware
│   └── fastapi.py        # FastAPI middleware
├── tests/
└── setup.py
```

### Java SDK

```java
// Maven/Gradle dependency
import com.silker.agent.SilkerAI;

SilkerAI agent = SilkerAI.builder()
    .apiKey("your-key")
    .debug(true)
    .build();

agent.init();

// Spring Boot integration
@Configuration
public class SilkerConfig {
    @Bean
    public SilkerFilter silkerFilter() {
        return new SilkerFilter("your-key");
    }
}

// Servlet Filter
@WebFilter(urlPatterns = "/*")
public class SilkerFilter implements Filter {
    // ...
}
```

**Struktura:**
```
silker-java/
├── src/main/java/com/silker/agent/
│   ├── SilkerAI.java
│   ├── DetectionEngine.java
│   ├── CloudClient.java
│   ├── Sanitization.java
│   └── filters/
│       ├── SpringFilter.java
│       └── ServletFilter.java
└── pom.xml / build.gradle
```

### Go SDK

```go
import "github.com/silker/agent"

agent := silker.New(silker.Config{
    APIKey: "your-key",
    Debug: true,
})

agent.Init()

// Gin integration
import "github.com/silker/agent/gin"

r := gin.Default()
r.Use(silker.GinMiddleware("your-key"))

// Echo integration
import "github.com/silker/agent/echo"

e.Use(silker.EchoMiddleware("your-key"))
```

## Strategia Implementacji

### Faza 1: Wspólny Protokół
1. **Dokumentacja API** - OpenAPI/Swagger spec
2. **Shared test suite** - Testy integracyjne dla protokołu
3. **Reference implementation** - Node.js SDK jako referencja

### Faza 2: Python SDK (najłatwiejszy start)
- Najprostszy do implementacji (podobna składnia)
- Popularny w web dev i data science
- Łatwa integracja z Flask/Django/FastAPI

### Faza 3: Java SDK
- Enterprise adoption
- Spring Boot integration
- Servlet API support

### Faza 4: Go SDK
- Wysoka wydajność
- Microservices
- Gin/Echo frameworks

## Współdzielone Komponenty

### Opcja 1: WebAssembly (WASM)
- Kompilacja logiki detekcji do WASM
- Współdzielenie między językami
- Wymaga kompilatora (AssemblyScript/Rust)

### Opcja 2: Shared Rules Config
- YAML/JSON z regułami
- Każdy SDK parsuje i implementuje lokalnie
- Prostsze, ale duplikacja kodu

### Opcja 3: Hybrid Approach (Rekomendowane)
- **Lokalna detekcja** - nativna implementacja w każdym języku
- **Cloud API** - wspólny protokół REST
- **Rules** - dokumentacja + przykłady implementacji
- **Sanityzacja** - wspólna specyfikacja, nativna implementacja

## Przykład: Python SDK Structure

```
silker-python/
├── silker/
│   ├── __init__.py
│   ├── agent.py              # SilkerAI.init, emitWorkflowEvent
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── anomaly.py        # isAnomaly()
│   │   ├── rate_limit.py     # checkRateLimit()
│   │   ├── sqli.py           # SQLi detection
│   │   ├── xss.py            # XSS detection
│   │   └── owasp/            # OWASP Top 10
│   ├── cloud/
│   │   ├── __init__.py
│   │   ├── communication.py  # sendToCloud()
│   │   └── sanitization.py   # sanitizeSensitiveData()
│   ├── analytics/
│   │   ├── performance.py
│   │   └── user_behavior.py
│   ├── monitoring/
│   │   ├── audit.py
│   │   └── health.py
│   └── integrations/
│       ├── flask.py
│       ├── django.py
│       └── fastapi.py
├── tests/
├── examples/
└── setup.py
```

## API Consistency Across Languages

Wszystkie SDK powinny mieć **identyczne API**:

```typescript
// TypeScript (obecny)
await SilkerAI.init({ apiKey: 'key' });
SilkerAI.emitWorkflowEvent({ method: 'POST', url: '/api' });
```

```python
# Python (przyszły)
silker.init(api_key='key')
silker.emit_workflow_event(method='POST', url='/api')
```

```java
// Java (przyszły)
SilkerAI.init(new SilkerOptions().setApiKey("key"));
SilkerAI.emitWorkflowEvent(new SilkerEvent().setMethod("POST").setUrl("/api"));
```

## Zalecenia

1. **Zacznij od Python SDK** - najłatwiejszy, duża społeczność
2. **Użyj OpenAPI spec** - automatyczna generacja klientów
3. **Wspólne testy integracyjne** - testuj protokół, nie implementację
4. **Dokumentacja reguł** - YAML/JSON z przykładami dla każdego języka
5. **CI/CD dla wszystkich SDK** - automatyczne testy i publikacja

## Roadmap

- [x] Node.js SDK (obecny)
- [ ] Python SDK (następny)
- [ ] Java SDK
- [ ] Go SDK
- [ ] OpenAPI specification
- [ ] Shared test suite
- [ ] Documentation site (multi-language)

