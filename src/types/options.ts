/**
 * Strategia obsługi wykrytych danych wrażliwych (PII).
 */
export type DataLeakageStrategy = 'block' | 'redact' | 'monitor';

/**
 * Konfiguracja wykrywania wycieku danych.
 */
export interface DataLeakageConfig {
  strategy: DataLeakageStrategy;
  piiPatterns?: {
    email?: boolean;
    phone?: boolean;
    creditCard?: boolean;
    ssn?: boolean;
    pesel?: boolean;
  };
}

/**
 * Dostępne profile konfiguracyjne.
 */
export type ConfigProfile = 'strict' | 'saas' | 'audit';

/**
 * Funkcjonalności Silker AI do włączania/wyłączania.
 */
export interface SilkerFeatures {
  /** Wykrywanie limitu szybkości (rate limiting) */
  rateLimit?: boolean;
  /** Wykrywanie ataków SQL injection */
  sqliDetection?: boolean;
  /** Wykrywanie ataków XSS */
  xssDetection?: boolean;
  /** Wykrywanie path traversal */
  pathTraversalDetection?: boolean;
  /** Wykrywanie ataków CSRF */
  csrfDetection?: boolean;
  /** Wykrywanie ataków SSRF */
  ssrfDetection?: boolean;
  /** Wykrywanie ataków IDOR */
  idorDetection?: boolean;
  /** Wykrywanie host header injection */
  hostHeaderInjectionDetection?: boolean;
  /** Walidacja nagłówków bezpieczeństwa */
  securityHeadersValidation?: boolean;
  /** Wykrywanie wycieku danych (boolean lub obiekt konfiguracyjny ze strategią) */
  dataLeakageDetection?: boolean | DataLeakageConfig;
  /** Walidacja schematu API */
  apiSchemaValidation?: boolean;
  /** Wykrywanie anomalii sesji */
  sessionAnomaliesDetection?: boolean;
  /** Wykrywanie ataków na upload plików */
  fileUploadDetection?: boolean;
  /** Wykrywanie ataków przez zewnętrzne integracje */
  thirdPartyDetection?: boolean;
  /** Wykrywanie naruszeń compliance */
  complianceDetection?: boolean;
  /** Sprawdzanie threat intelligence */
  threatIntelligence?: boolean;
  /** Wykrywanie naruszeń zero-trust */
  zeroTrustDetection?: boolean;
  /** Logowanie audytu */
  auditLogging?: boolean;
  /** Komunikacja z chmurą */
  cloudCommunication?: boolean;
  /** Wykrywanie broken access control */
  accessControlDetection?: boolean;
  /** Walidacja kryptograficzna */
  cryptographicValidation?: boolean;
  /** Wykrywanie podatnych komponentów */
  vulnerableComponentsDetection?: boolean;
  /** Walidacja autentykacji */
  authenticationValidation?: boolean;
  /** Walidacja integralności oprogramowania */
  softwareIntegrityValidation?: boolean;
  /** Wykrywanie prompt injection dla systemów AI/LLM */
  promptInjectionDetection?: boolean;
  /** Automatyczne banowanie adresów IP po wykryciu ataku lub przekroczeniu limitów */
  ipBanning?: boolean;
  /** Wyłącza legacy web security (CSRF, SSRF, IDOR, Host Header) - dla użytkowników z Cloudflare/WAF */
  disableLegacySecurity?: boolean;
}

/**
 * Konfiguracja telemetrii (wysyłka eventów do platformy).
 */
export interface TelemetryOptions {
  /**
   * Udział wysyłanych zwykłych request-eventów (0..1).
   * Threaty są zawsze wysyłane (100%). Domyślnie 1 (wszystkie requesty).
   * Niższa wartość zmniejsza koszt ingestu i narzut sieciowy przy dużym ruchu.
   */
  sampleRate?: number;
}

/**
 * Konfiguracja rate limiting.
 */
export interface RateLimitConfig {
  /** Okno czasowe w milisekundach (domyślnie 60000 = 1 minuta) */
  windowMs?: number;
  /** Maksymalna liczba żądań w oknie czasowym (domyślnie 60 = ~1 req/sek) */
  maxRequests?: number;
  /** Czas trwania blokady IP w milisekundach po przekroczeniu limitu (domyślnie 60000 = 1 minuta) */
  banDurationMs?: number;
}

/**
 * Opcje konfiguracyjne dla Silker AI.
 */
export interface SilkerOptions {
  /** Profil konfiguracyjny (opcjonalny, nadpisywany przez explicit features) */
  profile?: ConfigProfile;
  /** Klucz API do komunikacji z chmurą (domyślnie: process.env.SILKER_API_KEY; bez klucza SDK działa w trybie detection-only) */
  apiKey?: string;
  /** Identyfikator aplikacji używany do grupowania danych w dashboardzie (domyślnie: process.env.SILKER_APP_ID; opcjonalny — platforma rozwiązuje app po kluczu API) */
  appId?: string;
  /** Opcjonalny endpoint chmury (domyślnie: process.env.SILKER_ENDPOINT, potem https://platform.silkerai.com w produkcji, http://localhost:3000 w trybie dev) */
  endpoint?: string;
  /** Włącza tryb debugowania z dodatkowymi logami */
  debug?: boolean;
  /** Funkcjonalności do włączania/wyłączania (domyślnie wszystkie włączone) */
  features?: SilkerFeatures;
  /** Maksymalny rozmiar payloadu w bajtach (domyślnie 1MB) */
  maxPayloadSize?: number;
  /** Lista dozwolonych hostów dla walidacji Host header (opcjonalne, domyślnie brak walidacji) */
  allowedHosts?: string[];
  /** Konfiguracja rate limiting (opcjonalne, domyślnie 60 req/min) */
  rateLimit?: RateLimitConfig;
  /** Blokowanie WYCHODZĄCYCH żądań fetch po wykryciu anomalii (domyślnie false — tryb monitor-only, tylko telemetria) */
  blockOutgoing?: boolean;
  /**
   * Pobieranie konfiguracji funkcjonalności z dashboardu (domyślnie true).
   * Gdy true, flagi `features` zarządzane w panelu Silker nadpisują lokalne ustawienia
   * przy każdej synchronizacji telemetrii — bez potrzeby redeployu.
   * Ustaw `false`, aby trzymać konfigurację wyłącznie w kodzie/env.
   */
  remoteConfig?: boolean;
  /** Konfiguracja telemetrii (sampling request-eventów) */
  telemetry?: TelemetryOptions;
  /**
   * Hook przedłużający życie funkcji serverless (np. Vercel `waitUntil` / Next `after`).
   * Pozwala dostarczyć telemetrię po wysłaniu odpowiedzi BEZ blokowania ścieżki żądania.
   * Jeśli nie podano, telemetria jest wysyłana fire-and-forget (nigdy nie blokuje odpowiedzi).
   */
  waitUntil?: (promise: Promise<unknown>) => void;
}
