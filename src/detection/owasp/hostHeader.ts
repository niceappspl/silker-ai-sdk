import { SilkerEvent, SilkerOptions } from '../../types';

/**
 * Wykrywa potencjalne ataki Host Header Injection.
 * Sprawdza czy nagłówek Host zawiera znaki nowej linii lub nie jest na liście dozwolonych hostów.
 * @param event - Zdarzenie do sprawdzenia
 * @param headers - Nagłówki HTTP żądania
 * @param allowedHosts - Opcjonalna lista dozwolonych hostów (z opcji konfiguracyjnych)
 * @returns true jeśli wykryto potencjalny atak Host Header Injection, false w przeciwnym razie
 */
export function detectHostHeaderInjection(event: SilkerEvent, headers?: any, allowedHosts?: string[]): boolean {
  if (!headers) return false;
  
  const hostKey = Object.keys(headers).find(key => key.toLowerCase() === 'host');
  const hostHeader = hostKey ? headers[hostKey] : undefined;
  
  if (hostHeader) {
    if (typeof hostHeader !== 'string') return true;

    if (hostHeader.includes('\n') || hostHeader.includes('\r')) {
      return true;
    }

    if (allowedHosts && allowedHosts.length > 0) {
        const cleanHost = hostHeader.split(':')[0];
        if (!allowedHosts.some(allowed => cleanHost === allowed || hostHeader === allowed)) {
            return true;
        }
    }
  }
  return false;
}
