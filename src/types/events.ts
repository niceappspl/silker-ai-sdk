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
  /** Tagi compliance dla raportowania (np. GDPR, AI_ACT_RESILIENCE) */
  complianceTags?: string[];
  /** Typy wykrytych danych wrażliwych (np. email, phone, credit_card) */
  dataTypesDetected?: string[];
  /**
   * Kierunek ruchu: incoming = Express/Edge middleware (request od klienta),
   * outgoing = przechwycony fetch() (egress z backendu).
   */
  direction?: 'incoming' | 'outgoing';
}
