import { VibeGuardEvent } from '../types';

/**
 * Wykrywa potencjalny wyciek danych wrażliwych.
 * Skanuje payload lub odpowiedź pod kątem kluczy API, sekretów, PII i danych dostępowych do bazy.
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

  const apiKeyPatterns = [
    /"api_key"\s*:\s*"([^"]{15,})"/gi,
    /"api-key"\s*:\s*"([^"]{15,})"/gi,
    /"apiKey"\s*:\s*"([^"]{15,})"/gi,
    /'api[_-]?key'\s*:\s*'([^']{15,})'/gi,
    /api[_-]?key[_-]?[=:]\s*['"]?([a-zA-Z0-9_-]{15,})['"]?/gi,
    /bearer\s+([a-zA-Z0-9_\-\.]{15,})/gi,
    /authorization[_-]?[=:]\s*['"]?bearer\s+([a-zA-Z0-9_\-\.]{15,})['"]?/gi,
    /x[_-]?api[_-]?key[_-]?[=:]\s*['"]?([a-zA-Z0-9_-]{15,})['"]?/gi,
  ];

  const secretPatterns = [
    /"password"\s*:\s*"([^"]{6,})"/gi,
    /'password'\s*:\s*'([^']{6,})'/gi,
    /password[_-]?[=:]\s*['"]?([^'"\s]{6,})['"]?/gi,
    /"secret"\s*:\s*"([^"]{10,})"/gi,
    /'secret'\s*:\s*'([^']{10,})'/gi,
    /secret[_-]?[=:]\s*['"]?([^'"\s]{10,})['"]?/gi,
    /"token"\s*:\s*"([^"]{10,})"/gi,
    /'token'\s*:\s*'([^']{10,})'/gi,
    /token[_-]?[=:]\s*['"]?([^'"\s]{10,})['"]?/gi,
  ];

  const piiPatterns = [
    /\b\d{3}-\d{2}-\d{4}\b/g,
    /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    /\b\d{10,15}\b/g,
  ];

  const dbPatterns = [
    /mysql[_-]?[=:]\s*['"]?([^'"\s]+)['"]?/gi,
    /postgres[_-]?[=:]\s*['"]?([^'"\s]+)['"]?/gi,
    /mongodb[_-]?[=:]\s*['"]?([^'"\s]+)['"]?/gi,
    /connection[_-]?string[_-]?[=:]\s*['"]?([^'"\s]{20,})['"]?/gi,
  ];

  const allPatterns = [
    ...apiKeyPatterns.map(p => ({ pattern: p, type: 'API Key' })),
    ...secretPatterns.map(p => ({ pattern: p, type: 'Secret' })),
    ...piiPatterns.map(p => ({ pattern: p, type: 'PII' })),
    ...dbPatterns.map(p => ({ pattern: p, type: 'Database Credential' })),
  ];

  for (const { pattern, type } of allPatterns) {
    const regex = new RegExp(pattern.source, pattern.flags);
    const matches = Array.from(contentToCheck.matchAll(regex));
    for (const m of matches) {
      findings.push(`${type}: ${m[0].substring(0, 50)}...`);
      if (findings.length >= 5) break;
    }
    if (findings.length >= 5) break;
  }

  return { leaked: findings.length > 0, findings };
}

