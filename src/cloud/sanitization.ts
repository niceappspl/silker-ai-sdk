/**
 * Sanityzuje dane wrażliwe, maskując hasła, tokeny, klucze API i inne poufne informacje.
 * Rekurencyjnie przetwarza obiekty i tablice, maskując wartości w polach wrażliwych.
 * @param data - Dane do sanityzacji (string, obiekt lub tablica)
 * @returns Zsanityzowane dane z zamaskowanymi wartościami wrażliwymi
 */
export function sanitizeSensitiveData(data: any): any {
  if (!data) return data;

  const sensitiveKeys = [
    'password', 'secret', 'token', 'key', 'apikey', 'api_key',
    'authorization', 'auth', 'bearer', 'credentials', 'private_key',
    'database_url', 'db_url', 'connection_string', 'jwt_secret',
    'ssn', 'social_security', 'credit_card', 'cc_number', 'email',
    'phone', 'phone_number', 'address', 'zipcode', 'postal_code'
  ];

  if (typeof data === 'string') {
    let sanitized = data;
    sensitiveKeys.forEach(key => {
      const regex = new RegExp(`("${key}"\\s*:\\s*)"([^"]{4,})"`, 'gi');
      sanitized = sanitized.replace(regex, '$1"***MASKED***"');
    });
    return sanitized;
  }

  if (typeof data === 'object') {
    const sanitized: any = Array.isArray(data) ? [] : {};
    for (const [key, value] of Object.entries(data)) {
      if (sensitiveKeys.some(sensitive => key.toLowerCase().includes(sensitive))) {
        sanitized[key] = '***MASKED***';
      } else {
        sanitized[key] = sanitizeSensitiveData(value);
      }
    }
    return sanitized;
  }

  return data;
}

