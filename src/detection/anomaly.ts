import { VibeGuardEvent, VibeGuardOptions } from '../types';
import { checkRateLimit } from './rateLimit';
import { detectCsrfAttack, detectSsrfAttack, detectIdorAttack, detectHostHeaderInjection, detectBrokenAccessControl, detectPrivilegeEscalation, detectHorizontalPrivilegeEscalation } from './owasp';
import { detectDataLeakage } from './dataLeakage';
import { detectFileUploadAttack } from './fileUpload';
import { detectThirdPartyAttack } from './thirdParty';
import { detectComplianceViolation } from './compliance';
import { checkThreatIntelligence } from './threatIntelligence';
import { detectZeroTrustViolation } from './zeroTrust';
import { detectSessionAnomalies } from '../analytics/userBehavior';
import { validateSecurityHeaders } from '../validation/securityHeaders';
import { performApiValidation } from '../validation/apiSchema';
import { checkCryptographicFailures, detectWeakEncryption } from './cryptographic';
import { detectVulnerableComponents, checkForCveReferences } from './vulnerableComponents';
import { detectAuthenticationFailures } from './authentication';
import { checkSoftwareIntegrity } from './softwareIntegrity';

let globalOptions: VibeGuardOptions | null = null;

/**
 * Sprawdza czy funkcjonalność jest włączona (domyślnie true).
 */
function isFeatureEnabled(feature: keyof NonNullable<VibeGuardOptions['features']>): boolean {
  if (!globalOptions?.features) {
    return true;
  }
  return globalOptions.features[feature] !== false;
}

/**
 * Ustawia globalne opcje dla modułu detekcji anomalii.
 * @param options - Opcje konfiguracyjne VibeGuard
 */
export function setGlobalOptions(options: VibeGuardOptions | null) {
  globalOptions = options;
}

/**
 * Sprawdza czy zdarzenie zawiera anomalie bezpieczeństwa.
 * Wykonuje szereg testów bezpieczeństwa: rate limiting, SQLi, XSS, OWASP Top 10,
 * wyciek danych, upload plików, compliance, threat intelligence i zero-trust.
 * @param event - Zdarzenie do sprawdzenia
 * @returns true jeśli wykryto anomalie, false w przeciwnym razie
 */
export function isAnomaly(event: VibeGuardEvent): boolean {
  const { method, url, payload, ip, headers } = event;

  if (isFeatureEnabled('rateLimit') && ip && checkRateLimit(event)) {
    return true;
  }

  if (payload && typeof payload === 'string') {
    if (isFeatureEnabled('sqliDetection')) {
      const sqliPatterns = [
        /(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b).*(\bFROM\b|\bWHERE\b|\bINTO\b)/i,
        /('|(\\x27)|(\\x2D\\x2D)|(\\x23)|(\\x3B)|(\\x2F\\x2A)|(\\x2A\\x2F))/i
      ];

      for (const pattern of sqliPatterns) {
        if (pattern.test(payload)) {
          return true;
        }
      }
    }

    if (isFeatureEnabled('xssDetection')) {
      const xssPatterns = [
        /<script[^>]*>.*?<\/script>/i,
        /javascript:/i,
        /on\w+\s*=/i,
        /<iframe[^>]*>/i
      ];

      for (const pattern of xssPatterns) {
        if (pattern.test(payload)) {
          return true;
        }
      }
    }
  }

  if (ip && (ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.'))) {
    return false;
  }

  if (isFeatureEnabled('pathTraversalDetection') && (url.includes('../') || url.includes('..\\'))) {
    return true;
  }

  if (isFeatureEnabled('csrfDetection') && detectCsrfAttack(event, headers)) {
    return true;
  }

  if (isFeatureEnabled('ssrfDetection') && detectSsrfAttack(event)) {
    return true;
  }

  if (isFeatureEnabled('idorDetection') && detectIdorAttack(event, payload)) {
    return true;
  }

  if (isFeatureEnabled('hostHeaderInjectionDetection') && detectHostHeaderInjection(event, headers)) {
    return true;
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

  if (isFeatureEnabled('securityHeadersValidation')) {
    const headerValidation = validateSecurityHeaders(headers);
    if (!headerValidation.valid && headers) {
      if (globalOptions?.debug) {
        console.log('⚠️ Missing security headers:', headerValidation.missing);
      }
    }
  }

  if (isFeatureEnabled('dataLeakageDetection') && (event.method === 'GET' || event.method === 'POST')) {
    const leakageCheck = detectDataLeakage(event.payload);
    if (leakageCheck.leaked) {
      if (globalOptions?.debug) {
        console.log('🚨 Data leakage detected:', leakageCheck.findings);
      }
      if (event.method === 'POST') {
        return true;
      }
    }
  }

  if (isFeatureEnabled('apiSchemaValidation') && event.url.includes('/api/') && event.payload) {
    const apiValidation = performApiValidation(event);
    if (!apiValidation.valid && globalOptions?.debug) {
      console.log('⚠️ API schema validation warnings:', apiValidation.warnings);
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
      if (globalOptions?.debug) {
        console.log('🕵️ Threat intelligence alert:', threatCheck.details);
      }
      return true;
    }
  }

  if (isFeatureEnabled('zeroTrustDetection') && detectZeroTrustViolation(event)) {
    return true;
  }

  return false;
}

