import { VibeGuardEvent } from '../types';

/**
 * Wykonuje weryfikację zgodności z zasadami zero-trust.
 * Sprawdza autentykację, weryfikację pochodzenia, user-agent i dodatkowe potwierdzenia dla operacji destrukcyjnych.
 * @param event - Zdarzenie do sprawdzenia
 * @returns Obiekt z flagą weryfikacji i listą brakujących wymagań
 */
export function performZeroTrustCheck(event: VibeGuardEvent): { verified: boolean; requirements: string[] } {
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

  const now = new Date();
  const hour = now.getHours();
  if (hour < 6 || hour > 22) {
    requirements.push('Access outside normal business hours requires additional verification');
  }

  return { verified: requirements.length === 0, requirements };
}

/**
 * Wykrywa naruszenia zasad zero-trust.
 * @param event - Zdarzenie do sprawdzenia
 * @returns true jeśli wykryto naruszenie zasad zero-trust, false w przeciwnym razie
 */
export function detectZeroTrustViolation(event: VibeGuardEvent): boolean {
  const zeroTrustCheck = performZeroTrustCheck(event);

  if (!zeroTrustCheck.verified) {
    return zeroTrustCheck.requirements.some(req =>
      req.includes('Missing authentication') ||
      req.includes('Destructive operation requires confirmation')
    );
  }

  return false;
}

