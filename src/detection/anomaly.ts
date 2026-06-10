import { SilkerEvent, SilkerOptions, DataLeakageConfig } from '../types';
import { checkRateLimit } from './rateLimit';
import { detectCsrfAttack, detectSsrfAttack, detectIdorAttack, detectHostHeaderInjection, detectBrokenAccessControl, detectPrivilegeEscalation, detectHorizontalPrivilegeEscalation } from './owasp';
import { detectDataLeakage } from './dataLeakage';
import { detectFileUploadAttack } from './fileUpload';
import { detectThirdPartyAttack } from './thirdParty';
import { detectComplianceViolation } from './compliance';
import { checkThreatIntelligence } from './threatIntelligence';
import { detectZeroTrustViolation } from './zeroTrust';
import { detectSessionAnomalies } from '../analytics/userBehavior';
import { checkCryptographicFailures, detectWeakEncryption } from './cryptographic';
import { detectVulnerableComponents, checkForCveReferences } from './vulnerableComponents';
import { detectAuthenticationFailures } from './authentication';
import { checkSoftwareIntegrity } from './softwareIntegrity';
import { detectPromptInjection } from './promptInjection';
import { detectSqliHeuristic, detectXssHeuristic } from './heuristics';
import { isLlmRoute } from './llmContext';

let globalOptions: SilkerOptions | null = null;

type FeatureKey = keyof NonNullable<SilkerOptions['features']>;

/**
 * Domyślny stan funkcjonalności gdy użytkownik nie ustawił ich jawnie.
 * Detektory generujące dużo false positives na normalnym ruchu produkcyjnym
 * są OPT-IN (false) — włącza się je jawnie przez options.features.
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
 * Sprawdza czy funkcjonalność jest włączona.
 * Jawna wartość użytkownika (boolean/obiekt) wygrywa; undefined → DEFAULT_FEATURES.
 */
function isFeatureEnabled(feature: FeatureKey): boolean {
  const featureValue = globalOptions?.features?.[feature];
  if (featureValue === undefined) {
    return DEFAULT_FEATURES[feature] ?? false;
  }
  if (typeof featureValue === 'object') {
    return true;
  }
  return featureValue === true;
}

/**
 * Pobiera konfigurację data leakage detection.
 * false → null (wyłączone); undefined/true → domyślna strategia 'block'; obiekt → bez zmian.
 */
function getDataLeakageConfig(): DataLeakageConfig | null {
  const config = globalOptions?.features?.dataLeakageDetection;
  if (config === false) {
    return null;
  }
  if (config === undefined || config === true) {
    return { strategy: 'block' };
  }
  return config;
}

/**
 * Sprawdza czy legacy security jest wyłączone.
 */
function isLegacySecurityDisabled(): boolean {
  return globalOptions?.features?.disableLegacySecurity === true;
}

/**
 * Ustawia globalne opcje dla modułu detekcji anomalii.
 * @param options - Opcje konfiguracyjne Silker
 */
export function setGlobalOptions(options: SilkerOptions | null) {
  globalOptions = options;
}

/**
 * Stosuje konfigurację funkcjonalności pobraną z dashboardu (zwracaną w odpowiedzi ingest).
 * Dashboard jest źródłem prawdy — nadpisuje lokalne flagi, dzięki czemu użytkownik może
 * włączać/wyłączać ochronę z panelu bez redeployu aplikacji.
 * Pomija wartości inne niż boolean (np. obiekt dataLeakage ustawiony jawnie w kodzie zostaje).
 */
export function applyRemoteFeatures(features: Record<string, unknown> | null | undefined): void {
  if (!features || typeof features !== 'object') return;
  if (!globalOptions) globalOptions = {};
  const merged = { ...(globalOptions.features ?? {}) } as Record<string, unknown>;
  for (const [key, value] of Object.entries(features)) {
    if (typeof value === 'boolean') {
      merged[key] = value;
    }
  }
  globalOptions.features = merged as SilkerOptions['features'];

  // Apply rate limit threshold from dashboard if provided as a number.
  const maxReqs = (features as Record<string, unknown>)['rateLimitMaxRequests'];
  if (typeof maxReqs === 'number' && maxReqs > 0) {
    const { setRateLimitConfig } = require('./rateLimit') as typeof import('./rateLimit');
    setRateLimitConfig({ maxRequests: maxReqs });
  }
}

/**
 * Sprawdza czy zdarzenie zawiera anomalie bezpieczeństwa.
 * Wykonuje szereg testów bezpieczeństwa: rate limiting, SQLi, XSS, OWASP Top 10,
 * wyciek danych, upload plików, compliance, threat intelligence i zero-trust.
 * @param event - Zdarzenie do sprawdzenia
 * @returns true jeśli wykryto anomalie, false w przeciwnym razie
 */
export function isAnomaly(event: SilkerEvent): boolean {
  try {
    const { method, url, payload, ip, headers } = event;
    const maxPayloadSize = globalOptions?.maxPayloadSize || 1048576; // Default 1MB

    // Rate limiting check (lightweight, do first)
    const ipBanningEnabled = isFeatureEnabled('ipBanning');
    if (isFeatureEnabled('rateLimit') && ip && checkRateLimit(event, ipBanningEnabled)) {
      return true;
    }

    // Prepare payload for scanning (truncate to avoid ReDoS/DoS)
    let scannedPayload = '';
    
    if (payload && typeof payload === 'string') {
      scannedPayload = payload.length > maxPayloadSize ? payload.substring(0, maxPayloadSize) : payload;
    } else if (payload) {
      try {
        const str = JSON.stringify(payload);
        scannedPayload = str.length > maxPayloadSize ? str.substring(0, maxPayloadSize) : str;
      } catch (e) {
        // Circular reference or other error, ignore payload
      }
    }

    // PRIORITY: For LLM routes, run prompt injection check FIRST
    // Block on ANY detection for LLM routes (stricter than generic endpoints)
    const isLlm = isLlmRoute(url, headers);
    if (isLlm && scannedPayload && isFeatureEnabled('promptInjectionDetection')) {
      const injection = detectPromptInjection(scannedPayload);
      if (injection.detected) {
        event.complianceTags = [...(event.complianceTags || []), 'AI_ACT_RESILIENCE', 'ISO_A_8_2'];
        return true;
      }
    }

    // Standard payload checks
    if (scannedPayload) {
      if (isFeatureEnabled('sqliDetection')) {
        if (detectSqliHeuristic(scannedPayload)) {
          return true;
        }
      }

      if (isFeatureEnabled('xssDetection')) {
        if (detectXssHeuristic(scannedPayload)) {
          return true;
        }
      }

      // For non-LLM routes, check prompt injection with severity threshold
      if (!isLlm && isFeatureEnabled('promptInjectionDetection')) {
        const injection = detectPromptInjection(scannedPayload);
        if (injection.detected && (injection.severity === 'high' || injection.severity === 'critical')) {
          event.complianceTags = [...(event.complianceTags || []), 'AI_ACT_RESILIENCE'];
          return true;
        }
      }
    }

    if (isFeatureEnabled('pathTraversalDetection')) {
      const pathTraversalPatterns = ['../', '..\\'];
      const urlHasTraversal = pathTraversalPatterns.some(pattern => url.includes(pattern));
      const payloadHasTraversal = scannedPayload && pathTraversalPatterns.some(pattern => scannedPayload.includes(pattern));

      if (urlHasTraversal || payloadHasTraversal) {
        return true;
      }
    }

    // Legacy Web Security Checks (grouped for easy disabling)
    if (!isLegacySecurityDisabled()) {
      if (isFeatureEnabled('csrfDetection') && detectCsrfAttack(event, headers)) {
        return true;
      }

      if (isFeatureEnabled('ssrfDetection') && detectSsrfAttack(event)) {
        return true;
      }

      if (isFeatureEnabled('idorDetection') && detectIdorAttack(event, scannedPayload)) {
        return true;
      }

      if (isFeatureEnabled('hostHeaderInjectionDetection') && detectHostHeaderInjection(event, headers, globalOptions?.allowedHosts)) {
        return true;
      }
    }

    if (isFeatureEnabled('accessControlDetection')) {
      const userRole = (event as any).userRole || headers?.['x-user-role'];
      if (detectBrokenAccessControl(event, userRole)) {
        return true;
      }
      if ((event as any).currentRole && (event as any).targetRole) {
        if (detectPrivilegeEscalation(event, (event as any).currentRole, (event as any).targetRole)) {
          return true;
        }
      }
      if ((event as any).userId && (event as any).resourceUserId) {
        if (detectHorizontalPrivilegeEscalation(event, (event as any).userId, (event as any).resourceUserId)) {
          return true;
        }
      }
    }

    if (isFeatureEnabled('cryptographicValidation')) {
      const cryptoCheck = checkCryptographicFailures(event);
      if (!cryptoCheck.valid && cryptoCheck.issues.some(issue => issue.includes('plaintext password') || issue.includes('credit card'))) {
        return true;
      }
      if (detectWeakEncryption(headers)) {
        return true;
      }
    }

    if (isFeatureEnabled('vulnerableComponentsDetection')) {
      const vulnerabilities = detectVulnerableComponents(event);
      if (vulnerabilities.some(v => v.risk === 'critical' || v.risk === 'high')) {
        return true;
      }
      const cves = checkForCveReferences(event);
      if (cves.length > 0) {
        return true;
      }
    }

    if (isFeatureEnabled('authenticationValidation')) {
      const authIssues = detectAuthenticationFailures(event);
      if (authIssues.some(issue => issue.severity === 'critical' || issue.severity === 'high')) {
        return true;
      }
    }

    if (isFeatureEnabled('softwareIntegrityValidation')) {
      const integrityIssues = checkSoftwareIntegrity(event);
      if (integrityIssues.some(issue => issue.severity === 'critical' || issue.severity === 'high')) {
        return true;
      }
    }

    // Data Leakage Detection with strategy support
    const dataLeakageConfig = getDataLeakageConfig();
    if (dataLeakageConfig && dataLeakageConfig.strategy === 'block' && (method === 'GET' || method === 'POST')) {
      const leakageCheck = detectDataLeakage(scannedPayload);
      if (leakageCheck.leaked) {
        event.complianceTags = [...(event.complianceTags || []), 'GDPR', 'GDPR_ART_32'];
        
        const isAuthEndpoint = /\/(login|register|auth|signin|signup)/i.test(url);
        
        const hasHighRiskLeak = leakageCheck.findings.some((finding: string) =>
          finding.includes('Credit Card') ||
          finding.includes('SSN') ||
          finding.includes('Private Key') ||
          finding.includes('Database Connection')
        );

        const hasPasswordLeak = leakageCheck.findings.some((finding: string) =>
          finding.includes('Password')
        );

        const hasApiKeyLeak = leakageCheck.findings.some((finding: string) =>
          finding.includes('API Key') ||
          finding.includes('Secret') ||
          finding.includes('JWT Token')
        );

        if (hasHighRiskLeak) {
          return true;
        }

        if (hasPasswordLeak && !isAuthEndpoint) {
          return true;
        }

        if (method === 'GET' && hasApiKeyLeak) {
          return true;
        }
      }
    }

    if (isFeatureEnabled('sessionAnomaliesDetection') && detectSessionAnomalies(event)) {
      return true;
    }

    if (isFeatureEnabled('fileUploadDetection') && detectFileUploadAttack(event)) {
      return true;
    }

    if (isFeatureEnabled('thirdPartyDetection') && detectThirdPartyAttack(event)) {
      return true;
    }

    if (isFeatureEnabled('complianceDetection') && detectComplianceViolation(event)) {
      return true;
    }

    if (isFeatureEnabled('threatIntelligence')) {
      const threatCheck = checkThreatIntelligence(event);
      if (threatCheck.threat) {
        return true;
      }
    }

    if (isFeatureEnabled('zeroTrustDetection') && detectZeroTrustViolation(event)) {
      event.complianceTags = [...(event.complianceTags || []), 'NIST_ZT'];
      return true;
    }

    return false;
  } catch (error) {
    return false;
  }
}

export { getDataLeakageConfig };
