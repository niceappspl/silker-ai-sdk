/**
 * Klasa błędu VibeGuard.
 */
export class VibeGuardError extends Error {
  /**
   * Tworzy nowy błąd VibeGuard.
   * @param message - Komunikat błędu
   * @param code - Kod błędu
   */
  constructor(message: string, public code: string) {
    super(message);
    this.name = 'VibeGuardError';
  }
}

