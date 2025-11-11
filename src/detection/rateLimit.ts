import { VibeGuardEvent } from '../types';

const rateLimitMap = new Map<string, { count: number; resetTime: number }>();

/**
 * Sprawdza czy żądanie przekracza limit szybkości (rate limit).
 * Używa okna czasowego 1 minuty z limitem 5 żądań na IP.
 * Automatycznie czyści wygasłe wpisy z mapy.
 * @param event - Zdarzenie do sprawdzenia
 * @returns true jeśli przekroczono limit szybkości, false w przeciwnym razie
 */
export function checkRateLimit(event: VibeGuardEvent): boolean {
  if (!event.ip) return false;

  const now = Date.now();
  const windowMs = 60000;
  const key = `${event.ip}:${Math.floor(now / windowMs)}`;
  let current = rateLimitMap.get(key);

  if (!current || current.resetTime <= now) {
    current = { count: 0, resetTime: now + windowMs };
    rateLimitMap.set(key, current);
  }

  current.count++;
  
  if (current.count > 5) {
    return true;
  }

  // Cleanup expired entries
  for (const [k, v] of rateLimitMap.entries()) {
    if (v.resetTime < now) rateLimitMap.delete(k);
  }

  return false;
}

