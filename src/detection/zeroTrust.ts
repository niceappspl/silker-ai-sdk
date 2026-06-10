import { SilkerEvent } from '../types';

/** Konfiguracja sprawdzeń zero-trust. */
export interface ZeroTrustCheckConfig {
  /**
   * Wymaga dodatkowej weryfikacji poza "godzinami pracy" (6-23 czasu serwera).
   * Domyślnie WYŁĄCZONE — dla globalnych API ruch nocny jest normalny.
   */
  businessHoursCheck?: boolean;
}

/**
 * Wykonuje weryfikację zgodności z zasadami zero-trust.
 * Sprawdza autentykację, weryfikację pochodzenia, user-agent i dodatkowe potwierdzenia dla operacji destrukcyjnych.
 * @param event - Zdarzenie do sprawdzenia
 * @param config - Opcjonalna konfiguracja (businessHoursCheck domyślnie off)
 * @returns Obiekt z flagą weryfikacji i listą brakujących wymagań
 */
export function performZeroTrustCheck(event: SilkerEvent, config?: ZeroTrustCheckConfig): { verified: boolean; requirements: string[] } {
  const requirements: string[] = [];

  const authHeaders = ['authorization', 'x-api-key', 'authentication'];
  const hasAuth = authHeaders.some(header => {
    const headerLower = header.toLowerCase();
    return event.headers?.[header] || 
           event.headers?.[headerLower] || 
           event.headers?.[header.toUpperCase()] ||
           Object.keys(event.headers || {}).some(k => k.toLowerCase() === headerLower);
  });

  if (!hasAuth && !event.url.includes('/login') && !event.url.includes('/auth')) {
    requirements.push('Missing authentication credentials');
  }

  const origin = event.headers?.['origin'] || event.headers?.['referer'];
  if (event.method !== 'GET' && !origin && !event.url.includes('/api/')) {
    requirements.push('Missing request origin verification');
  }

  if (!event.userAgent) {
    requirements.push('Missing user agent for device verification');
  }

  if (event.method === 'DELETE' && !event.url.includes('/api/')) {
    const verificationHeaders = ['x-confirmation-token', 'x-delete-confirmation'];
    const hasVerification = verificationHeaders.some(header =>
      event.headers?.[header] || event.headers?.[header.toLowerCase()]
    );

    if (!hasVerification) {
      requirements.push('Destructive operation requires confirmation token');
    }
  }

  // Heurystyka "godzin pracy" jest jawnie opt-in — globalne API mają legalny ruch 24/7.
  if (config?.businessHoursCheck === true) {
    const now = new Date();
    const hour = now.getHours();
    if (hour < 6 || hour > 23) {
      requirements.push('Access outside normal business hours requires additional verification');
    }
  }

  return { verified: requirements.length === 0, requirements };
}

/**
 * Wykrywa naruszenia zasad zero-trust.
 * @param event - Zdarzenie do sprawdzenia
 * @returns true jeśli wykryto naruszenie zasad zero-trust, false w przeciwnym razie
 */
export function detectZeroTrustViolation(event: SilkerEvent): boolean {
  const zeroTrustCheck = performZeroTrustCheck(event);

  if (!zeroTrustCheck.verified) {
    return zeroTrustCheck.requirements.some(req =>
      req.includes('Missing authentication') ||
      req.includes('Destructive operation requires confirmation')
    );
  }

  return false;
}

