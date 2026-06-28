import { SilkerEvent } from '../types';

/**
 * Endpointy, na których wysyłanie haseł / danych logowania jest oczekiwanym
 * zachowaniem użytkownika (nie wyciekiem ani atakiem supply-chain).
 */
export function isAuthEndpoint(url: string): boolean {
  return /\/(login|register|auth|signin|signup|session|token|password-reset|forgot-password|reset-password|oauth)/i.test(
    url
  );
}

/** POST/PUT/PATCH na auth endpoint = przesłanie credentials do aplikacji klienta. */
export function isCredentialSubmission(event: SilkerEvent): boolean {
  const method = (event.method || 'GET').toUpperCase();
  if (method !== 'POST' && method !== 'PUT' && method !== 'PATCH') {
    return false;
  }
  return isAuthEndpoint(event.url || '');
}
