import { SilkerEvent, SilkerOptions } from '../types';
import { detectCsrfAttack, detectSsrfAttack, detectIdorAttack, detectHostHeaderInjection } from './owasp';
import { detectPromptInjection } from './promptInjection';
import { checkRateLimit } from './rateLimit';
import { detectDataLeakage } from './dataLeakage';

let globalOptions: SilkerOptions | null = null;

export function setGlobalOptionsForThreat(options: SilkerOptions | null) {
  globalOptions = options;
}

function isFeatureEnabled(feature: keyof NonNullable<SilkerOptions['features']>): boolean {
  if (!globalOptions?.features) {
    return false;
  }
  return globalOptions.features[feature] === true;
}

export interface ThreatInfo {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
}

/**
 * Określa typ zagrożenia na podstawie wykrytej anomalii.
 * @param event - Zdarzenie które wywołało anomalie
 * @returns Informacje o zagrożeniu lub null
 */
export function detectThreatType(event: SilkerEvent): ThreatInfo | null {
  const { method, url, payload, ip, headers } = event;

  if (!globalOptions?.features) {
    return null;
  }

  const payloadStr = typeof payload === 'string' ? payload : JSON.stringify(payload || '');

  if (globalOptions.features.sqliDetection) {
    const sqliPatterns = [
      /(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b).*(\bFROM\b|\bWHERE\b|\bINTO\b)/i,
      /('|(\\x27)|(\\x2D\\x2D)|(\\x23)|(\\x3B)|(\\x2F\\x2A)|(\\x2A\\x2F))/i
    ];

    for (const pattern of sqliPatterns) {
      if (pattern.test(payloadStr)) {
        return {
          type: 'SQL Injection',
          severity: 'critical',
          description: `SQL injection pattern detected in ${url}`
        };
      }
    }
  }

  if (globalOptions.features.xssDetection) {
    const xssPatterns = [
      /<script[^>]*>/i,
      /<\/script>/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /<iframe[^>]*>/i,
      /<svg[^>]*>/i,
      /<embed[^>]*>/i,
      /<object[^>]*>/i
    ];

    for (const pattern of xssPatterns) {
      if (pattern.test(payloadStr)) {
        return {
          type: 'XSS',
          severity: 'high',
          description: `Cross-site scripting attempt detected in ${url}`
        };
      }
    }
  }

  if (globalOptions.features.pathTraversalDetection) {
    const pathTraversalPatterns = ['../', '..\\'];
    const urlHasTraversal = pathTraversalPatterns.some(pattern => url.includes(pattern));
    const payloadHasTraversal = payloadStr && pathTraversalPatterns.some(pattern => payloadStr.includes(pattern));

    if (urlHasTraversal || payloadHasTraversal) {
      return {
        type: 'Path Traversal',
        severity: 'high',
        description: `Directory traversal attempt detected in ${url}`
      };
    }
  }

  if (globalOptions.features.promptInjectionDetection) {
    const promptPatterns = [
      /ignore\s+(all\s+)?previous\s+instructions/i,
      /print\s+everything\s+above/i,
      /you\s+are\s+now\s+a/i,
      /dan\s+mode/i,
      /jailbreak/i
    ];

    for (const pattern of promptPatterns) {
      if (pattern.test(payloadStr)) {
        return {
          type: 'Prompt Injection',
          severity: 'high',
          description: `AI prompt injection attempt detected in ${url}`
        };
      }
    }
  }

  if (isFeatureEnabled('rateLimit') && ip) {
    if (checkRateLimit(event)) {
      return {
        type: 'Rate Limiting',
        severity: 'medium',
        description: `Rate limit exceeded from IP ${ip}`
      };
    }
  }

  if (isFeatureEnabled('csrfDetection') && detectCsrfAttack(event, headers)) {
    return {
      type: 'CSRF',
      severity: 'high',
      description: `CSRF attack detected in ${url}`
    };
  }

  if (isFeatureEnabled('ssrfDetection') && detectSsrfAttack(event)) {
    return {
      type: 'SSRF',
      severity: 'critical',
      description: `Server-side request forgery attempt detected in ${url}`
    };
  }

  if (isFeatureEnabled('idorDetection') && detectIdorAttack(event, payloadStr)) {
    return {
      type: 'IDOR',
      severity: 'high',
      description: `Insecure direct object reference detected in ${url}`
    };
  }

  if (isFeatureEnabled('hostHeaderInjectionDetection') && detectHostHeaderInjection(event, headers)) {
    return {
      type: 'Host Header Injection',
      severity: 'high',
      description: `Host header injection attempt detected in ${url}`
    };
  }

  if (isFeatureEnabled('dataLeakageDetection')) {
    const leakageCheck = detectDataLeakage(payloadStr);
    if (leakageCheck.leaked) {
      return {
        type: 'Data Leakage',
        severity: 'critical',
        description: `Sensitive data leakage detected: ${leakageCheck.findings.join(', ')}`
      };
    }
  }

  return {
    type: 'Security Anomaly',
    severity: 'medium',
    description: `Security threat detected in ${url}`
  };
}

