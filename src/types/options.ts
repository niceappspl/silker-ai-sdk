/**
 * Funkcjonalności VibeGuard do włączania/wyłączania.
 */
export interface VibeGuardFeatures {
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
  /** Monitorowanie wydajności */
  performanceMonitoring?: boolean;
  /** Komunikacja z chmurą */
  cloudCommunication?: boolean;
}

/**
 * Opcje konfiguracyjne dla VibeGuard.
 */
export interface VibeGuardOptions {
  /** Klucz API wymagany do komunikacji z chmurą */
  apiKey: string;
  /** Opcjonalny endpoint chmury (domyślnie: https://vibeguard.cloudflareworkers.com/api) */
  endpoint?: string;
  /** Włącza tryb debugowania z dodatkowymi logami */
  debug?: boolean;
  /** Włącza tryb proxy HTTP */
  proxyMode?: boolean;
  /** Funkcjonalności do włączania/wyłączania (domyślnie wszystkie włączone) */
  features?: VibeGuardFeatures;
}

