import { VibeGuardEvent } from '../types';

/**
 * Waliduje schemat API dla żądania.
 * Sprawdza wymagane pola, formaty danych i zgodność z konwencjami API.
 * @param event - Zdarzenie do walidacji
 * @param payload - Opcjonalny payload do walidacji
 * @returns Obiekt z flagą ważności i listą błędów
 */
export function validateApiSchema(event: VibeGuardEvent, payload?: any): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  let data: any;
  try {
    data = typeof payload === 'string' ? JSON.parse(payload) : payload;
  } catch (error) {
    if (payload !== undefined && payload !== null) {
      errors.push('Invalid JSON payload');
    }
    return { valid: errors.length === 0, errors };
  }

  if (payload === undefined || payload === null) {
    return { valid: true, errors };
  }

  if ((event.url.includes('/user') || event.url.includes('/account')) && !event.url.includes('/users') && !event.url.includes('/accounts')) {
    const userFields = ['id', 'email', 'name', 'username'];
    const hasRequiredFields = userFields.some(field =>
      data[field] !== undefined || data.data?.[field] !== undefined
    );

    if (!hasRequiredFields && Object.keys(data).length > 0) {
      errors.push('User/Account endpoint missing required fields');
    }

    const email = data.email || data.data?.email;
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      errors.push('Invalid email format');
    }
  }

  if (event.url.includes('/api/')) {
    if (data !== null && typeof data !== 'object' && !Array.isArray(data)) {
      errors.push('API endpoint should return object or array');
    }

    if (event.url.includes('/list') || event.url.includes('/search') || event.url.includes('?')) {
      if (data && data.data && !Array.isArray(data.data) && typeof data.data !== 'object') {
        errors.push('List/search endpoints should have data array or object');
      }
    }
  }

  if (event.url.match(/\/\d+/)) {
    const urlParts = event.url.split('/');
    const id = urlParts[urlParts.length - 1];

    if (id && (!/^\d+$/.test(id) || (id.length > 50 && /^\d+$/.test(id)))) {
      errors.push('Suspicious ID format in URL');
    }
  }

  if (event.url.includes('?')) {
    try {
      const url = new URL(event.url, 'http://localhost');
      const params = url.searchParams;

      for (const [key, value] of params) {
        if (value.length > 1000) {
          errors.push(`Parameter '${key}' value too long`);
        }

        if (value.match(/(\bUNION\b|\bSELECT\b|\bDROP\b|\bDELETE\b)/i)) {
          errors.push(`Parameter '${key}' contains suspicious SQL patterns`);
        }
      }
    } catch (error) {
      // Ignore URL parsing errors
    }
  }

  if (['POST', 'PUT', 'PATCH'].includes(event.method)) {
    const contentType = event.headers?.['content-type'] || event.headers?.['Content-Type'];
    if (contentType && !contentType.includes('application/json') && typeof data === 'object') {
      errors.push('JSON payload should have application/json Content-Type');
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Sprawdza zgodność z konwencjami OpenAPI.
 * Weryfikuje strukturę odpowiedzi, typy danych i formaty błędów.
 * @param event - Zdarzenie do sprawdzenia
 * @param payload - Opcjonalny payload do sprawdzenia
 * @returns Obiekt z flagą zgodności i listą problemów
 */
export function validateOpenApiCompliance(event: VibeGuardEvent, payload?: any): { compliant: boolean; issues: string[] } {
  const issues: string[] = [];

  if (!payload) return { compliant: true, issues };

  try {
    const data = typeof payload === 'string' ? JSON.parse(payload) : payload;

    if (data.error && typeof data.error !== 'string' && typeof data.error !== 'object') {
      issues.push('Error field should be string or object');
    }

    if (data.message && typeof data.message !== 'string') {
      issues.push('Message field should be string');
    }

    if (data.status && (data.status < 100 || data.status > 599)) {
      issues.push('Invalid HTTP status code');
    }

    const booleanFields = ['success', 'ok', 'valid'];
    booleanFields.forEach(field => {
      if (data[field] !== undefined && typeof data[field] !== 'boolean') {
        issues.push(`Field '${field}' should be boolean`);
      }
    });

  } catch (error) {
    issues.push('Invalid JSON structure');
  }

  return { compliant: issues.length === 0, issues };
}

/**
 * Wykonuje pełną walidację API dla zdarzenia.
 * Łączy walidację schematu i zgodności OpenAPI.
 * @param event - Zdarzenie do walidacji
 * @returns Obiekt z flagą ważności i listą ostrzeżeń
 */
export function performApiValidation(event: VibeGuardEvent): { valid: boolean; warnings: string[] } {
  const warnings: string[] = [];

  try {
    const payload = event.payload ? JSON.parse(event.payload) : null;

    const schemaCheck = validateApiSchema(event, payload);
    if (!schemaCheck.valid) {
      warnings.push(...schemaCheck.errors);
    }

    const openApiCheck = validateOpenApiCompliance(event, payload);
    if (!openApiCheck.compliant) {
      warnings.push(...openApiCheck.issues);
    }

  } catch (error) {
    warnings.push('API validation failed');
  }

  return { valid: warnings.length === 0, warnings };
}

