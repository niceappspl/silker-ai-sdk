import { SilkerEvent } from '../../types';

/**
 * Wykrywa potencjalne ataki Host Header Injection.
 * Sprawdza czy nagłówek Host zawiera znaki nowej linii lub nie jest na liście dozwolonych hostów.
 * @param event - Zdarzenie do sprawdzenia
 * @param headers - Nagłówki HTTP żądania
 * @returns true jeśli wykryto potencjalny atak Host Header Injection, false w przeciwnym razie
 */
export function detectHostHeaderInjection(event: SilkerEvent, headers?: any): boolean {
  if (!headers) return false;
  
  const hostKey = Object.keys(headers).find(key => key.toLowerCase() === 'host');
  const hostHeader = hostKey ? headers[hostKey] : undefined;
  
  if (hostHeader) {
    if (hostHeader.includes('\n') || hostHeader.includes('\r')) {
      return true;
    }

    const expectedHosts = process.env.SILKER_ALLOWED_HOSTS?.split(',') || [];
    if (expectedHosts.length > 0 && !expectedHosts.some(host => hostHeader.includes(host))) {
      return true;
    }
  }
  return false;
}

