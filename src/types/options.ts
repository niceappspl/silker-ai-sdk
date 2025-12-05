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
  /** Wykrywanie wycieku danych */
  dataLeakageDetection?: boolean;
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
}

/**
 * Opcje konfiguracyjne dla Silker AI.
 */
export interface SilkerOptions {
  /** Klucz API wymagany do komunikacji z chmurą */
  apiKey: string;
  /** Identyfikator aplikacji używany do grupowania danych w dashboardzie */
  appId?: string;
  /** Opcjonalny endpoint chmury (domyślnie: https://api.silkerai.com w produkcji, http://localhost:3000 w trybie dev) */
  endpoint?: string;
  /** Włącza tryb debugowania z dodatkowymi logami */
  debug?: boolean;
  /** Funkcjonalności do włączania/wyłączania (domyślnie wszystkie włączone) */
  features?: SilkerFeatures;
  /** Maksymalny rozmiar payloadu w bajtach (domyślnie 50KB) */
  maxPayloadSize?: number;
}
