/**
 * Zdarzenie monitorowane przez Silker AI.
 */
export interface SilkerEvent {
  /** Metoda HTTP żądania */
  method: string;
  /** URL żądania */
  url: string;
  /** Opcjonalna zawartość żądania (payload) */
  payload?: any;
  /** Opcjonalny adres IP klienta */
  ip?: string;
  /** Znacznik czasu zdarzenia */
  timestamp: number;
  /** Opcjonalny nagłówek User-Agent */
  userAgent?: string;
  /** Opcjonalne nagłówki HTTP */
  headers?: Record<string, string>;
}

export type VibeGuardEvent = SilkerEvent;

