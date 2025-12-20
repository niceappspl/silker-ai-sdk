import { SilkerEvent, RateLimitConfig } from '../types';

const rateLimitMap = new Map<string, { count: number; resetTime: number }>();

let rateLimitConfig: RateLimitConfig = {
  windowMs: 60000,
  maxRequests: 5
};

/**
 * Ustawia globalną konfigurację rate limiting.
 * @param config - Nowa konfiguracja rate limiting
 */
export function setRateLimitConfig(config: RateLimitConfig): void {
  rateLimitConfig = { ...rateLimitConfig, ...config };
}

/**
 * Czyści stan rate limitera. Używane głównie w testach.
 */
export function clearRateLimitState(): void {
  rateLimitMap.clear();
}

/**
 * Sprawdza czy żądanie przekracza limit szybkości (rate limit).
 * Używa konfigurowalnego okna czasowego i limitu żądań.
 * Automatycznie czyści wygasłe wpisy z mapy.
 * @param event - Zdarzenie do sprawdzenia
 * @returns true jeśli przekroczono limit szybkości, false w przeciwnym razie
 */
export function checkRateLimit(event: SilkerEvent): boolean {
  if (!event.ip) return false;

  const now = Date.now();
  const windowMs = rateLimitConfig.windowMs || 60000;
  const maxRequests = rateLimitConfig.maxRequests || 5;
  const key = `${event.ip}:${Math.floor(now / windowMs)}`;
  let current = rateLimitMap.get(key);

  if (!current || current.resetTime <= now) {
    current = { count: 0, resetTime: now + windowMs };
    rateLimitMap.set(key, current);
  }

  current.count++;
  
  if (current.count > maxRequests) {
    return true;
  }

  // Cleanup expired entries
  for (const [k, v] of rateLimitMap.entries()) {
    if (v.resetTime < now) rateLimitMap.delete(k);
  }

  return false;
}

