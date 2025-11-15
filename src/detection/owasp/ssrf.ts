import { SilkerEvent } from '../../types';

/**
 * Wykrywa potencjalne ataki SSRF (Server-Side Request Forgery).
 * Sprawdza czy URL zawiera adresy wewnętrzne, localhost, lub metadane chmury.
 * @param event - Zdarzenie do sprawdzenia
 * @returns true jeśli wykryto potencjalny atak SSRF, false w przeciwnym razie
 */
export function detectSsrfAttack(event: SilkerEvent): boolean {
  if (!event.url) return false;

  const url = event.url.toLowerCase();
  const ssrfPatterns = [
    /localhost/i,
    /127\.0\.0\.1/,
    /0\.0\.0\.0/,
    /10\.\d+\.\d+\.\d+/,
    /172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/,
    /192\.168\.\d+\.\d+/,
    /169\.254\.\d+\.\d+/,
    /::1/,
    /internal/i,
    /metadata\.google/i,
    /169\.254\.169\.254/,
    /fd00:/,
    /\[::1\]/
  ];

  for (const pattern of ssrfPatterns) {
    if (pattern.test(url)) {
      return true;
    }
  }

  return false;
}

