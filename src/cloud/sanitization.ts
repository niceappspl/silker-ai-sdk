/**
 * Sanityzuje dane wrażliwe, maskując hasła, tokeny, klucze API i inne poufne informacje.
 * Rekurencyjnie przetwarza obiekty i tablice, maskując wartości w polach wrażliwych.
 * @param data - Dane do sanityzacji (string, obiekt lub tablica)
 * @returns Zsanityzowane dane z zamaskowanymi wartościami wrażliwymi
 */
export function sanitizeSensitiveData(data: any): any {
  if (!data) return data;

  // Rozszerzona lista kluczy wrażliwych
  const sensitiveKeys = [
    'password', 'pass', 'pwd', 'secret', 'token', 'key', 'apikey', 'api_key',
    'authorization', 'auth', 'bearer', 'credentials', 'private_key', 'privatekey',
    'database_url', 'db_url', 'connection_string', 'jwt_secret', 'jwt',
    'ssn', 'social_security', 'credit_card', 'cc_number', 'cvv', 'cvc', 
    'email', 'phone', 'phone_number', 'address', 'zipcode', 'postal_code',
    'access_token', 'refresh_token', 'id_token', 'session_id', 'cookie',
    'x-api-key', 'x-auth-token'
  ];

  if (typeof data === 'string') {
    // 1. Próba parsowania JSON (np. body requestu może być stringiem JSON)
    try {
      const parsed = JSON.parse(data);
      // Jeśli to był JSON, sanityzujemy go rekurencyjnie i zwracamy jako string
      if (typeof parsed === 'object') {
        return JSON.stringify(sanitizeSensitiveData(parsed));
      }
    } catch (e) {
      // Nie jest to JSON, kontynuujemy sanityzację tekstu
    }

    let sanitized = data;

    // 2. Maskowanie wzorców Regex w tekście (np. w URLach, logach, nagłówkach)
    
    // Credit Cards (Luhn alg check is overkill here, just simple pattern)
    // Matches 4 groups of 4 digits, or continuous 16 digits
    sanitized = sanitized.replace(/\b(?:\d[ -]*?){13,16}\b/g, '***CREDIT_CARD***');

    // Email addresses
    sanitized = sanitized.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '***EMAIL***');

    // JSON-like string patterns "key": "value"
    sensitiveKeys.forEach(key => {
      // Escape special regex chars in key just in case
      const escapedKey = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      // Case insensitive match for "key": "value"
      const regex = new RegExp(`("${escapedKey}"\\s*:\\s*)"([^"]*)"`, 'gi');
      sanitized = sanitized.replace(regex, '$1"***MASKED***"');
    });

    return sanitized;
  }

  if (typeof data === 'object') {
    // Handle Date objects - return ISO string
    if (data instanceof Date) return data.toISOString();
    // Handle null
    if (data === null) return null;

    if (Array.isArray(data)) {
        return data.map(item => sanitizeSensitiveData(item));
    }

    const sanitized: any = {};
    for (const [key, value] of Object.entries(data)) {
      // Sprawdzenie czy klucz jest na liście wrażliwych (case insensitive)
      if (sensitiveKeys.some(sensitive => key.toLowerCase().includes(sensitive))) {
        sanitized[key] = '***MASKED***';
      } else {
        // Rekurencyjna sanityzacja wartości
        sanitized[key] = sanitizeSensitiveData(value);
      }
    }
    return sanitized;
  }

  return data;
}
