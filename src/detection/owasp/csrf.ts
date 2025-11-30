import { SilkerEvent } from '../../types';

/**
 * Wykrywa potencjalne ataki CSRF (Cross-Site Request Forgery).
 * Sprawdza czy żądania modyfikujące (POST, PUT, PATCH, DELETE) mają token CSRF.
 * @param event - Zdarzenie do sprawdzenia
 * @param headers - Nagłówki HTTP żądania
 * @returns true jeśli wykryto potencjalny atak CSRF, false w przeciwnym razie
 */
export function detectCsrfAttack(event: SilkerEvent, headers?: any): boolean {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(event.method)) {
    const csrfToken = headers?.['x-csrf-token'] || headers?.['csrf-token'];
    const hasCsrfInBody = event.payload && typeof event.payload === 'string' && (
      event.payload.includes('csrf') ||
      event.payload.includes('_token') ||
      event.payload.includes('authenticity_token')
    );

    if (!csrfToken && !hasCsrfInBody && !event.url.includes('/api/')) {
      return true;
    }
  }
  return false;
}
