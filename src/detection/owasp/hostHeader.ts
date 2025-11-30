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
    if (typeof hostHeader !== 'string') return true; // Host header must be a string

    if (hostHeader.includes('\n') || hostHeader.includes('\r')) {
      return true;
    }

    const allowedHosts = process.env.SILKER_ALLOWED_HOSTS?.split(',') || [];
    if (allowedHosts.length > 0) {
        const cleanHost = hostHeader.split(':')[0]; // Remove port if present
        if (!allowedHosts.some(allowed => cleanHost === allowed || hostHeader === allowed)) {
            return true;
        }
    }
  }
  return false;
}
