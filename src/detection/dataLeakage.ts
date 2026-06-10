import { SilkerEvent } from '../types';

/**
 * Wykrywa potencjalny wyciek danych wrażliwych.
 * Skanuje payload lub odpowiedź pod kątem kluczy API, sekretów, PII i danych dostępowych do bazy.
 * Używa algorytmu Luhn do walidacji numerów kart kredytowych.
 * Wykrywa specyficzne tokeny (Stripe, GitHub, AWS, Google, Slack) oraz generyczne klucze API.
 * @param payload - Opcjonalny payload żądania do sprawdzenia
 * @param response - Opcjonalna odpowiedź do sprawdzenia
 * @returns Obiekt z flagą wycieku i listą znalezionych problemów
 */

function stringifyRecursive(obj: any, visited = new WeakSet()): string {
  if (obj === null || obj === undefined) return '';
  if (typeof obj === 'string') return obj;
  if (typeof obj !== 'object') return String(obj);
  
  if (visited.has(obj)) return '[Circular]';
  
  try {
    return JSON.stringify(obj, (key, value) => {
      if (typeof value === 'object' && value !== null) {
        if (visited.has(value)) return '[Circular]';
        visited.add(value);
      }
      return value;
    });
  } catch (error) {
    return String(obj);
  }
}

/**
 * Waliduje numer karty kredytowej używając algorytmu Luhn (mod 10).
 * Eliminuje false positives dla przypadkowych ciągów cyfr.
 * @param cardNumber - Numer karty do walidacji (może zawierać spacje i myślniki)
 * @returns true jeśli numer przechodzi test Luhn, false w przeciwnym razie
 */
function luhnCheck(cardNumber: string): boolean {
  const digits = cardNumber.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  
  let sum = 0;
  let isEven = false;
  
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits[i], 10);
    
    if (isEven) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    
    sum += digit;
    isEven = !isEven;
  }
  
  return sum % 10 === 0;
}

export function detectDataLeakage(payload?: string, response?: any): { leaked: boolean; findings: string[] } {
  const findings: string[] = [];

  if (!payload && !response) return { leaked: false, findings };

  let contentToCheck: string;
  if (payload) {
    contentToCheck = payload;
  } else if (response) {
    contentToCheck = stringifyRecursive(response);
  } else {
    contentToCheck = '';
  }

  // 1. Wykrywanie kart kredytowych z walidacją Luhn
  const creditCardPattern = /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g;
  const creditCardMatches = Array.from(contentToCheck.matchAll(creditCardPattern));
  for (const match of creditCardMatches) {
    if (luhnCheck(match[0])) {
      findings.push(`Credit Card: ${match[0].substring(0, 19)}`);
      if (findings.length >= 10) break;
    }
  }

  // 2. Wykrywanie numerów Social Security Number (SSN)
  const ssnPattern = /\b\d{3}-\d{2}-\d{4}\b/g;
  const ssnMatches = Array.from(contentToCheck.matchAll(ssnPattern));
  for (const match of ssnMatches) {
    findings.push(`SSN: ${match[0]}`);
    if (findings.length >= 10) break;
  }

  // 3. Wykrywanie specyficznych kluczy API popularnych serwisów
  const specificApiKeyPatterns = [
    { pattern: /sk_live_[a-zA-Z0-9]{24,}/g, name: 'Stripe Live Key' },
    { pattern: /sk_test_[a-zA-Z0-9]{24,}/g, name: 'Stripe Test Key' },
    { pattern: /pk_live_[a-zA-Z0-9]{24,}/g, name: 'Stripe Publishable Key' },
    { pattern: /ghp_[a-zA-Z0-9]{36,}/g, name: 'GitHub Personal Token' },
    { pattern: /gho_[a-zA-Z0-9]{36,}/g, name: 'GitHub OAuth Token' },
    { pattern: /github_pat_[a-zA-Z0-9_]{82,}/g, name: 'GitHub Fine-grained Token' },
    { pattern: /AKIA[0-9A-Z]{16}/g, name: 'AWS Access Key' },
    { pattern: /AIza[0-9A-Za-z_-]{35}/g, name: 'Google API Key' },
    { pattern: /ya29\.[0-9A-Za-z_-]{68,}/g, name: 'Google OAuth Token' },
    { pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}/g, name: 'Slack Token' },
  ];

  for (const { pattern, name } of specificApiKeyPatterns) {
    const matches = Array.from(contentToCheck.matchAll(pattern));
    for (const match of matches) {
      findings.push(`API Key (${name}): ${match[0].substring(0, 30)}...`);
      if (findings.length >= 10) break;
    }
    if (findings.length >= 10) break;
  }

  // 4. Wykrywanie generycznych kluczy API
  const genericApiKeyPatterns = [
    /"api_?key"\s*:\s*"([a-zA-Z0-9_\-\.]{20,})"/gi,
    /"apiKey"\s*:\s*"([a-zA-Z0-9_\-\.]{20,})"/gi,
    /'api_?key'\s*:\s*'([a-zA-Z0-9_\-\.]{20,})'/gi,
    /api[_-]?key[=:]\s*['"]([a-zA-Z0-9_\-\.]{20,})['"]?/gi,
    /x-api-key[=:]\s*['"]?([a-zA-Z0-9_\-\.]{20,})['"]?/gi,
  ];

  for (const pattern of genericApiKeyPatterns) {
    const matches = Array.from(contentToCheck.matchAll(new RegExp(pattern.source, pattern.flags)));
    for (const match of matches) {
      const key = match[1] || match[0];
      // Pomijamy placeholder'y testowe
      if (key && !/^(test|demo|example|sample|xxx)/i.test(key)) {
        findings.push(`API Key: ${key.substring(0, 30)}...`);
        if (findings.length >= 10) break;
      }
    }
    if (findings.length >= 10) break;
  }

  // 5. Wykrywanie haseł w payload
  const passwordPatterns = [
    /"password"\s*:\s*"([^"]{6,})"/gi,
    /'password'\s*:\s*'([^']{6,})'/gi,
  ];

  for (const pattern of passwordPatterns) {
    const matches = Array.from(contentToCheck.matchAll(pattern));
    for (const match of matches) {
      const pwd = match[1];
      // Pomijamy placeholder'y i słabe hasła testowe
      if (pwd && !/^(password|test|demo|example|\*+|x+)/i.test(pwd)) {
        findings.push(`Password: ${pwd.substring(0, 20)}...`);
        if (findings.length >= 10) break;
      }
    }
    if (findings.length >= 10) break;
  }

  // 6. Wykrywanie sekretów (client_secret, secret_key itp.)
  const secretPatterns = [
    /"client_?secret"\s*:\s*"([a-zA-Z0-9_\-\.]{20,})"/gi,
    /"secret_?key"\s*:\s*"([a-zA-Z0-9_\-\.]{20,})"/gi,
    /secret[=:]\s*['"]([a-zA-Z0-9_\-\.]{20,})['"]?/gi,
  ];

  for (const pattern of secretPatterns) {
    const matches = Array.from(contentToCheck.matchAll(pattern));
    for (const match of matches) {
      const secret = match[1] || match[0];
      // Pomijamy sekret testowe
      if (secret && !/^(test|demo|example|sample)/i.test(secret)) {
        findings.push(`Secret: ${secret.substring(0, 30)}...`);
        if (findings.length >= 10) break;
      }
    }
    if (findings.length >= 10) break;
  }

  // 7. Wykrywanie tokenów JWT (Base64 encoded z sygnaturą)
  const jwtPattern = /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g;
  const jwtMatches = Array.from(contentToCheck.matchAll(jwtPattern));
  for (const match of jwtMatches) {
    findings.push(`JWT Token: ${match[0].substring(0, 50)}...`);
    if (findings.length >= 10) break;
  }

  // 8. Wykrywanie kluczy prywatnych (RSA, DSA, EC)
  // Bez flagi `g` - sprawdzamy tylko istnienie (stanowy lastIndex przy .test() jest pułapką).
  const privateKeyPattern = /-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----/;
  if (privateKeyPattern.test(contentToCheck)) {
    findings.push('Private Key: -----BEGIN PRIVATE KEY-----');
  }

  // 9. Wykrywanie connection stringów do baz danych
  const dbConnectionPatterns = [
    /mongodb(\+srv)?:\/\/[^\s"']+/gi,
    /postgres(ql)?:\/\/[^\s"']+/gi,
    /mysql:\/\/[^\s"']+/gi,
    /redis:\/\/[^\s"']+/gi,
  ];

  for (const pattern of dbConnectionPatterns) {
    const matches = Array.from(contentToCheck.matchAll(pattern));
    for (const match of matches) {
      findings.push(`Database Connection: ${match[0].substring(0, 40)}...`);
      if (findings.length >= 10) break;
    }
    if (findings.length >= 10) break;
  }

  return { leaked: findings.length > 0, findings };
}

