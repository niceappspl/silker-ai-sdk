/**
 * Odpowiedź z chmury VibeGuard po analizie zdarzenia.
 */
export interface CloudResponse {
  /** Czy żądanie powinno zostać zablokowane */
  block: boolean;
  /** Opcjonalny fragment kodu naprawczego */
  fixSnippet?: string;
  /** Opcjonalny poziom zagrożenia */
  severity?: 'low' | 'medium' | 'high';
  /** Opcjonalny identyfikator alertu */
  alertId?: string;
}

