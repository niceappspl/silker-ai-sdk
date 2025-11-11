/**
 * Waliduje nagłówki bezpieczeństwa HTTP.
 * Sprawdza obecność wymaganych nagłówków bezpieczeństwa.
 * @param headers - Nagłówki HTTP do sprawdzenia
 * @returns Obiekt z flagą ważności i listą brakujących nagłówków
 */
export function validateSecurityHeaders(headers?: any): { valid: boolean; missing: string[] } {
  const requiredHeaders = [
    'x-content-type-options',
    'x-frame-options',
    'x-xss-protection',
    'strict-transport-security'
  ];

  const missing: string[] = [];
  const headersLower = headers ? Object.keys(headers).map(h => h.toLowerCase()) : [];

  for (const header of requiredHeaders) {
    if (!headersLower.includes(header)) {
      missing.push(header);
    }
  }

  return { valid: missing.length === 0, missing };
}

