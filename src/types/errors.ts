/**
 * Klasa błędu Silker.
 */
export class SilkerError extends Error {
  /**
   * Tworzy nowy błąd Silker.
   * @param message - Komunikat błędu
   * @param code - Kod błędu
   */
  constructor(message: string, public code: string) {
    super(message);
    this.name = 'SilkerError';
  }
}

