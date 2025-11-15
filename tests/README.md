# Testy Silker SDK

Wszystkie testy są zorganizowane w katalogu `tests/` z tą samą strukturą co `src/`.

## Struktura

```
tests/
├── index.test.ts                    # Testy głównego modułu
├── analytics/
│   ├── performance.test.ts
│   └── userBehavior.test.ts
├── cloud/
│   └── sanitization.test.ts
├── config/
│   └── runtime.test.ts
├── detection/
│   ├── compliance.test.ts
│   ├── dataLeakage.test.ts
│   ├── fileUpload.test.ts
│   ├── rateLimit.test.ts
│   ├── thirdParty.test.ts
│   ├── threatIntelligence.test.ts
│   ├── zeroTrust.test.ts
│   └── owasp/
│       ├── csrf.test.ts
│       ├── hostHeader.test.ts
│       ├── idor.test.ts
│       └── ssrf.test.ts
├── hooks/
│   ├── express.test.ts
│   └── fetch.test.ts
├── monitoring/
│   └── audit.test.ts
└── validation/
    ├── apiSchema.test.ts
    └── securityHeaders.test.ts
```

## Uruchamianie testów

```bash
# Wszystkie testy
npm test

# Testy w trybie watch
npm run test:watch

# Testy z pokryciem kodu
npm run test:coverage

# Tylko testy z katalogu tests/
npm run test:all
```

## Importy

Wszystkie testy importują moduły z `src/` używając względnych ścieżek:

```typescript
// Przykład dla tests/detection/compliance.test.ts
import { checkComplianceViolations } from '../../src/detection/compliance';
import { SilkerEvent } from '../../src/types';

// Przykład dla tests/detection/owasp/csrf.test.ts
import { detectCsrfAttack } from '../../../src/detection/owasp/csrf';
import { SilkerEvent } from '../../../src/types';
```

## Konfiguracja

Testy są konfigurowane przez `jest.config.js`:
- Szuka plików `*.test.ts` w katalogu `tests/`
- Zbiera pokrycie kodu z `src/` (wykluczając pliki `.d.ts`)

