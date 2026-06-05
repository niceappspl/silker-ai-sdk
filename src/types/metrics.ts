/**
 * Metryki wydajności żądania.
 */
export interface PerformanceMetrics {
  /** Endpoint żądania */
  endpoint: string;
  /** Metoda HTTP */
  method: string;
  /** Czas odpowiedzi w milisekundach */
  responseTime: number;
  /** Znacznik czasu */
  timestamp: number;
  /** Adres IP klienta */
  ip: string;
  /** Opcjonalny kod statusu HTTP */
  statusCode?: number;
}

/**
 * Wpis w dzienniku audytu.
 */
export interface AuditLogEntry {
  /** Unikalny identyfikator wpisu */
  id: string;
  /** Znacznik czasu */
  timestamp: number;
  /** Zdarzenie Silker */
  event: import('./events').SilkerEvent;
  /** Akcja wykonana na żądaniu */
  action: 'allowed' | 'blocked' | 'flagged' | 'redacted';
  /** Powód akcji */
  reason: string;
  /** Poziom ważności */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Opcjonalny identyfikator użytkownika */
  userId?: string;
  /** Opcjonalny identyfikator sesji */
  sessionId?: string;
  /** Opcjonalne dodatkowe metadane */
  metadata?: any;
  /** Tagi compliance dla raportowania (np. GDPR_ART_32, AI_ACT_RESILIENCE) */
  complianceTags?: string[];
  /** Typy wykrytych danych wrażliwych */
  dataTypesDetected?: string[];
}

/**
 * Zdarzenie uploadu pliku.
 */
export interface FileUploadEvent {
  /** Nazwa pliku */
  filename: string;
  /** Typ zawartości MIME */
  contentType: string;
  /** Rozmiar pliku w bajtach */
  size: number;
  /** Zawartość pliku (edge-safe: bez Node Buffer) */
  content: Uint8Array | string;
}

