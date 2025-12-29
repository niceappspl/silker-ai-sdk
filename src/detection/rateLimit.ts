import { SilkerEvent, RateLimitConfig } from '../types';

const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const banMap = new Map<string, { banUntil: number }>();

let rateLimitConfig: RateLimitConfig = {
  windowMs: 60000,
  maxRequests: 5,
  banDurationMs: 300000 // Default 5 minutes
};

/**
 * Ustawia globalną konfigurację rate limiting.
 * @param config - Nowa konfiguracja rate limiting
 */
export function setRateLimitConfig(config: RateLimitConfig): void {
  rateLimitConfig = { ...rateLimitConfig, ...config };
}

/**
 * Czyści stan rate limitera i banów. Używane głównie w testach.
 */
export function clearRateLimitState(): void {
  rateLimitMap.clear();
  banMap.clear();
}

/**
 * Sprawdza czy adres IP jest obecnie zbanowany.
 * @param ip - Adres IP do sprawdzenia
 * @returns true jeśli IP jest zbanowane, false w przeciwnym razie
 */
export function isIpBanned(ip: string | undefined): boolean {
  if (!ip) return false;
  
  const banInfo = banMap.get(ip);
  if (banInfo) {
    if (banInfo.banUntil > Date.now()) {
      return true;
    }
    // Ban expired
    banMap.delete(ip);
  }
  return false;
}

/**
 * Nakłada czasową blokadę na adres IP.
 * @param ip - Adres IP do zablokowania
 * @param durationMs - Czas trwania blokady w ms (opcjonalnie)
 */
export function banIp(ip: string | undefined, durationMs?: number): void {
  if (!ip) return;
  const duration = durationMs || rateLimitConfig.banDurationMs || 300000;
  banMap.set(ip, { banUntil: Date.now() + duration });
}

/**
 * Usuwa blokadę z adresu IP.
 * @param ip - Adres IP do odblokowania
 */
export function unbanIp(ip: string | undefined): void {
  if (!ip) return;
  banMap.delete(ip);
}

/**
 * Synchronizuje lokalną listę banów z danymi z dashboardu.
 * @param bannedIps - Lista zablokowanych IP z terminami wygaśnięcia
 */
export function syncBans(bannedIps: { ip: string, until: string }[]): void {
  // Clear expired or removed bans
  const incomingIps = new Set(bannedIps.map(b => b.ip));
  
  for (const ip of banMap.keys()) {
    if (!incomingIps.has(ip)) {
      banMap.delete(ip);
    }
  }

  // Add/Update bans from dashboard
  for (const item of bannedIps) {
    const duration = new Date(item.until).getTime() - Date.now();
    if (duration > 0) {
      banMap.set(item.ip, { banUntil: Date.now() + duration });
    }
  }
}

/**
 * Sprawdza czy żądanie przekracza limit szybkości (rate limit).
 * Używa konfigurowalnego okna czasowego i limitu żądań.
 * Automatycznie czyści wygasłe wpisy z mapy.
 * @param event - Zdarzenie do sprawdzenia
 * @returns true jeśli przekroczono limit szybkości lub IP jest zbanowane, false w przeciwnym razie
 */
export function checkRateLimit(event: SilkerEvent): boolean {
  if (!event.ip) return false;

  // Check if already banned
  if (isIpBanned(event.ip)) {
    return true;
  }

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
    // Automatically ban IP if rate limit is exceeded and banning is not disabled
    // Note: The caller (anomaly.ts) already checks isFeatureEnabled('rateLimit')
    // We should probably check ipBanning here too if we want it to be fully configurable
    return true;
  }

  // Periodic cleanup (10% chance to avoid overhead on every request)
  if (Math.random() < 0.1) {
    for (const [k, v] of rateLimitMap.entries()) {
      if (v.resetTime < now) rateLimitMap.delete(k);
    }
  }

  return false;
}

