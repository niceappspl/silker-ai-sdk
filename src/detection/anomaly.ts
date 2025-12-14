import { SilkerEvent, SilkerOptions } from '../types';
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
import { detectPromptInjection } from './promptInjection';
import { detectSqliHeuristic, detectXssHeuristic } from './heuristics';
import { createLogger } from '../utils/logger';

let globalOptions: SilkerOptions | null = null;

/**
 * Sprawdza czy funkcjonalność jest włączona (domyślnie true - włączona).
 */
function isFeatureEnabled(feature: keyof NonNullable<SilkerOptions['features']>): boolean {
  if (!globalOptions) {
    return true;
  }
  if (!globalOptions.features) {
    return true;
  }
  return globalOptions.features[feature] !== false;
}

/**
 * Ustawia globalne opcje dla modułu detekcji anomalii.
 * @param options - Opcje konfiguracyjne Silker
 */
export function setGlobalOptions(options: SilkerOptions | null) {
  globalOptions = options;
}

/**
 * Sprawdza czy zdarzenie zawiera anomalie bezpieczeństwa.
 * Wykonuje szereg testów bezpieczeństwa: rate limiting, SQLi, XSS, OWASP Top 10,
 * wyciek danych, upload plików, compliance, threat intelligence i zero-trust.
 * @param event - Zdarzenie do sprawdzenia
 * @returns true jeśli wykryto anomalie, false w przeciwnym razie
 */
export function isAnomaly(event: SilkerEvent): boolean {
  const logger = globalOptions ? createLogger(globalOptions) : null;

  // CRITICAL: Direct console.log to debug Vercel issue
  console.log('🔴 isAnomaly() CALLED with payload:', event.payload?.substring(0, 100));

  try {
    const { method, url, payload, ip, headers } = event;
    const maxPayloadSize = globalOptions?.maxPayloadSize || 51200; // Default 50KB

    // Rate limiting check (lightweight, do first)
    if (isFeatureEnabled('rateLimit') && ip && checkRateLimit(event)) {
      logger?.debug('🚫 BLOCKED: Rate limit exceeded');
      return true;
    }

    // IP Allowlist/Blocklist check (lightweight)
    if (ip && (ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.'))) {
      if (!isFeatureEnabled('zeroTrustDetection')) {
        return false;
      }
    }

    // Prepare payload for scanning (truncate to avoid ReDoS/DoS)
    let scannedPayload = '';
    
    console.log('🔴 Preparing scannedPayload, raw payload type:', typeof payload, 'length:', payload?.length);
    
    if (payload && typeof payload === 'string') {
      scannedPayload = payload.length > maxPayloadSize ? payload.substring(0, maxPayloadSize) : payload;
      console.log('🔴 scannedPayload from string, length:', scannedPayload.length);
    } else if (payload) {
      try {
        const str = JSON.stringify(payload);
        scannedPayload = str.length > maxPayloadSize ? str.substring(0, maxPayloadSize) : str;
        console.log('🔴 scannedPayload from JSON.stringify, length:', scannedPayload.length);
      } catch (e) {
        // Circular reference or other error, ignore payload
        console.log('🔴 Failed to stringify payload');
      }
    } else {
      console.log('🔴 payload is falsy');
    }

    console.log('🔴 Final scannedPayload length:', scannedPayload.length, 'Will check SQL?', scannedPayload.length > 0);

    if (scannedPayload) {
      if (isFeatureEnabled('sqliDetection')) {
        if (detectSqliHeuristic(scannedPayload)) {
          logger?.debug('🚫 BLOCKED: SQL injection detected');
          return true;
        }
      }

      if (isFeatureEnabled('xssDetection')) {
        if (detectXssHeuristic(scannedPayload)) {
          logger?.debug('🚫 BLOCKED: XSS detected (Heuristic)');
          return true;
        }
      }

      if (isFeatureEnabled('promptInjectionDetection')) {
        const injection = detectPromptInjection(scannedPayload);
        if (injection.detected && (injection.severity === 'high' || injection.severity === 'critical')) {
            logger?.debug('🚫 BLOCKED: Prompt Injection detected');
            return true;
        }
      }
    }

    if (isFeatureEnabled('pathTraversalDetection')) {
      const pathTraversalPatterns = ['../', '..\\'];
      const urlHasTraversal = pathTraversalPatterns.some(pattern => url.includes(pattern));
      // Check truncated payload for traversal too
      const payloadHasTraversal = scannedPayload && pathTraversalPatterns.some(pattern => scannedPayload.includes(pattern));

      if (urlHasTraversal || payloadHasTraversal) {
        logger?.debug('🚫 BLOCKED: Path traversal detected');
        return true;
      }
    }

    if (isFeatureEnabled('csrfDetection') && detectCsrfAttack(event, headers)) {
      return true;
    }

    if (isFeatureEnabled('ssrfDetection') && detectSsrfAttack(event)) {
      return true;
    }

    if (isFeatureEnabled('idorDetection') && detectIdorAttack(event, scannedPayload)) {
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
        logger?.debug('⚠️ Missing security headers:', headerValidation.missing);
      }
    }

    if (isFeatureEnabled('dataLeakageDetection') && (event.method === 'GET' || event.method === 'POST')) {
      // Use scannedPayload for leakage detection too
      const leakageCheck = detectDataLeakage(scannedPayload);
      if (leakageCheck.leaked) {
        logger?.debug('🚨 Data leakage detected:', leakageCheck.findings);
        
        const hasCriticalLeak = leakageCheck.findings.some((finding: string) =>
          finding.includes('credit card') ||
          finding.includes('SSN:') ||
          finding.includes('API key:')
        );

        if (event.method === 'GET' || hasCriticalLeak) {
          return true;
        }
      }
    }

    if (isFeatureEnabled('apiSchemaValidation') && event.url.includes('/api/') && scannedPayload) {
      const apiValidation = performApiValidation(event);
      if (!apiValidation.valid) {
        logger?.debug('⚠️ API schema validation warnings:', apiValidation.warnings);
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
        logger?.debug('🕵️ Threat intelligence alert:', threatCheck.details);
        return true;
      }
    }
    return false;
  } catch (error) {
    logger?.error('Silker AI Detection Error:', error);
    return false;
  }
}
