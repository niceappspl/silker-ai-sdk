import { SilkerOptions } from '../types';

export type FeatureKey = keyof NonNullable<SilkerOptions['features']>;

/**
 * Domyślny limit skanowanego payloadu (bajty) - współdzielony przez
 * express hook, edge core i isAnomaly. 100KB to balans między pokryciem
 * (typowe payloady ataków < 100KB) a kosztem CPU (regex/heurystyki).
 * Użytkownik może nadpisać przez `options.maxPayloadSize`.
 */
export const DEFAULT_SCAN_LIMIT_BYTES = 100 * 1024; // 100KB

/**
 * Domyślny stan funkcjonalności gdy użytkownik nie ustawił ich jawnie.
 * Detektory generujące dużo false positives na normalnym ruchu produkcyjnym
 * są OPT-IN (false) - włącza się je jawnie przez options.features.
 */
export const DEFAULT_FEATURES: Record<FeatureKey, boolean> = {
  // Włączone domyślnie (niski poziom false positives)
  rateLimit: true,
  sqliDetection: true,
  xssDetection: true,
  pathTraversalDetection: true,
  promptInjectionDetection: true,
  dataLeakageDetection: true,
  fileUploadDetection: true,
  ipBanning: true,
  auditLogging: true,
  cloudCommunication: true,
  // Ochrona SSRF dla WYCHODZĄCYCH żądań (fetch hook) - to główny cel hooka,
  // więc jest domyślnie WŁĄCZONA (w przeciwieństwie do incoming ssrfDetection).
  outboundSsrfProtection: true,
  // Opt-in (wysokie ryzyko false positives na produkcyjnych API)
  csrfDetection: false,
  ssrfDetection: false,
  idorDetection: false,
  hostHeaderInjectionDetection: false,
  securityHeadersValidation: false,
  apiSchemaValidation: false,
  sessionAnomaliesDetection: false,
  thirdPartyDetection: false,
  complianceDetection: false,
  threatIntelligence: false,
  zeroTrustDetection: false,
  accessControlDetection: false,
  cryptographicValidation: false,
  vulnerableComponentsDetection: false,
  authenticationValidation: false,
  softwareIntegrityValidation: false,
  disableLegacySecurity: false,
};

/**
 * Sprawdza czy funkcjonalność jest włączona - JEDYNE źródło prawdy dla
 * wszystkich modułów detekcji (anomaly, threatDetection, hooki).
 * Jawna wartość użytkownika (boolean/obiekt) wygrywa; undefined → DEFAULT_FEATURES.
 */
export function isFeatureEnabled(options: SilkerOptions | null, feature: FeatureKey): boolean {
  const featureValue = options?.features?.[feature];
  if (featureValue === undefined) {
    return DEFAULT_FEATURES[feature] ?? false;
  }
  if (typeof featureValue === 'object') {
    return true;
  }
  return featureValue === true;
}
