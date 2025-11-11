import { VibeGuardEvent } from '../types';
import { checkRateLimit } from './rateLimit';
import { detectCsrfAttack, detectSsrfAttack, detectIdorAttack, detectHostHeaderInjection } from './owasp';
import { detectDataLeakage } from './dataLeakage';
import { detectFileUploadAttack } from './fileUpload';
import { detectThirdPartyAttack } from './thirdParty';
import { detectComplianceViolation } from './compliance';
import { checkThreatIntelligence } from './threatIntelligence';
import { detectZeroTrustViolation } from './zeroTrust';
import { detectSessionAnomalies } from '../analytics/userBehavior';
import { validateSecurityHeaders } from '../validation/securityHeaders';
import { performApiValidation } from '../validation/apiSchema';

let globalOptions: { debug?: boolean } | null = null;

/**
 * Ustawia globalne opcje dla modułu detekcji anomalii.
 * @param options - Opcje konfiguracyjne z flagą debug
 */
export function setGlobalOptions(options: { debug?: boolean } | null) {
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

  if (ip && checkRateLimit(event)) {
    return true;
  }

  if (payload && typeof payload === 'string') {
    const sqliPatterns = [
      /(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b).*(\bFROM\b|\bWHERE\b|\bINTO\b)/i,
      /('|(\\x27)|(\\x2D\\x2D)|(\\x23)|(\\x3B)|(\\x2F\\x2A)|(\\x2A\\x2F))/i
    ];

    const xssPatterns = [
      /<script[^>]*>.*?<\/script>/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /<iframe[^>]*>/i
    ];

    for (const pattern of [...sqliPatterns, ...xssPatterns]) {
      if (pattern.test(payload)) {
        return true;
      }
    }
  }

  if (ip && (ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.'))) {
    return false;
  }

  if (url.includes('../') || url.includes('..\\')) {
    return true;
  }

  if (detectCsrfAttack(event, headers)) {
    return true;
  }

  if (detectSsrfAttack(event)) {
    return true;
  }

  if (detectIdorAttack(event, payload)) {
    return true;
  }

  if (detectHostHeaderInjection(event, headers)) {
    return true;
  }

  const headerValidation = validateSecurityHeaders(headers);
  if (!headerValidation.valid && headers) {
    if (globalOptions?.debug) {
      console.log('⚠️ Missing security headers:', headerValidation.missing);
    }
  }

  if (event.method === 'GET' || event.method === 'POST') {
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

  if (event.url.includes('/api/') && event.payload) {
    const apiValidation = performApiValidation(event);
    if (!apiValidation.valid && globalOptions?.debug) {
      console.log('⚠️ API schema validation warnings:', apiValidation.warnings);
    }
  }

  if (detectSessionAnomalies(event)) {
    return true;
  }

  if (detectFileUploadAttack(event)) {
    return true;
  }

  if (detectThirdPartyAttack(event)) {
    return true;
  }

  if (detectComplianceViolation(event)) {
    return true;
  }

  const threatCheck = checkThreatIntelligence(event);
  if (threatCheck.threat) {
    if (globalOptions?.debug) {
      console.log('🕵️ Threat intelligence alert:', threatCheck.details);
    }
    return true;
  }

  if (detectZeroTrustViolation(event)) {
    return true;
  }

  return false;
}

