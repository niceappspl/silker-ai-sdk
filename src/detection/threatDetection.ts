import { SilkerEvent, SilkerOptions } from '../types';
import { detectCsrfAttack, detectSsrfAttack, detectIdorAttack, detectHostHeaderInjection, detectBrokenAccessControl, detectPrivilegeEscalation, detectHorizontalPrivilegeEscalation } from './owasp';
import { classifyPromptInjection } from './promptInjection';
import { isLlmRoute } from './llmContext';
import { checkRateLimit } from './rateLimit';
import { detectDataLeakage } from './dataLeakage';
import { detectSqliHeuristic, detectXssHeuristic } from './heuristics';
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
import { FeatureKey, isFeatureEnabled as isFeatureEnabledShared } from './features';

let globalOptions: SilkerOptions | null = null;

export function setGlobalOptionsForThreat(options: SilkerOptions | null) {
  globalOptions = options;
}

/**
 * Współdzielony helper z ./features - ta sama semantyka co w isAnomaly:
 * undefined → DEFAULT_FEATURES (opt-in detektory są domyślnie wyłączone).
 */
function isFeatureEnabled(feature: FeatureKey): boolean {
  return isFeatureEnabledShared(globalOptions, feature);
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

  const payloadStr = typeof payload === 'string' ? payload : JSON.stringify(payload || '');

  // 1. SQL Injection
  if (isFeatureEnabled('sqliDetection')) {
    if (detectSqliHeuristic(payloadStr)) {
        return {
          type: 'SQL Injection',
          severity: 'critical',
          description: `SQL injection pattern detected in ${url}`
        };
    }
  }

  // 2. XSS
  if (isFeatureEnabled('xssDetection')) {
    if (detectXssHeuristic(payloadStr)) {
        return {
          type: 'XSS',
          severity: 'high',
          description: `Cross-site scripting attempt detected in ${url}`
        };
    }
  }

  // 3. Path Traversal
  if (isFeatureEnabled('pathTraversalDetection')) {
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

  // 4. Prompt Injection
  // Typ pozostaje "Prompt Injection" (dashboard "AI Security" matchuje ILIKE '%prompt injection%').
  // Podtyp (jailbreak / system_prompt_extraction / instruction_override / data_exfiltration_via_llm)
  // trafia do description, żeby panel mógł rozbić zagrożenia po klasie ataku.
  if (isFeatureEnabled('promptInjectionDetection')) {
    const classification = classifyPromptInjection(payloadStr);
    if (classification.detected && classification.subtype) {
      const onLlmRoute = isLlmRoute(url, headers);
      const context = onLlmRoute ? `on LLM route ${url}` : `in ${url}`;
      return {
        type: 'Prompt Injection',
        severity: classification.severity ?? 'high',
        description: `Prompt injection (${classification.subtype}) detected ${context}`,
      };
    }

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

  // 5. Rate Limiting
  if (isFeatureEnabled('rateLimit') && ip) {
    if (checkRateLimit(event)) {
      return {
        type: 'Rate Limiting',
        severity: 'medium',
        description: `Rate limit exceeded from IP ${ip}`
      };
    }
  }

  // 6. CSRF
  if (isFeatureEnabled('csrfDetection') && detectCsrfAttack(event, headers)) {
    return {
      type: 'CSRF',
      severity: 'high',
      description: `CSRF attack detected in ${url}`
    };
  }

  // 7. SSRF
  if (isFeatureEnabled('ssrfDetection') && detectSsrfAttack(event)) {
    return {
      type: 'SSRF',
      severity: 'critical',
      description: `Server-side request forgery attempt detected in ${url}`
    };
  }

  // 8. IDOR
  if (isFeatureEnabled('idorDetection') && detectIdorAttack(event, payloadStr)) {
    return {
      type: 'IDOR',
      severity: 'high',
      description: `Insecure direct object reference detected in ${url}`
    };
  }

  // 9. Host Header Injection
  if (isFeatureEnabled('hostHeaderInjectionDetection') && detectHostHeaderInjection(event, headers, globalOptions?.allowedHosts)) {
    return {
      type: 'Host Header Injection',
      severity: 'high',
      description: `Host header injection attempt detected in ${url}`
    };
  }

  // 10. Data Leakage
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

  // 11. File Upload
  if (isFeatureEnabled('fileUploadDetection') && detectFileUploadAttack(event)) {
    return {
      type: 'File Upload Attack',
      severity: 'high',
      description: `Malicious file upload attempt detected in ${url}`
    };
  }

  // 12. Third Party / Supply Chain
  if (isFeatureEnabled('thirdPartyDetection') && detectThirdPartyAttack(event)) {
    return {
        type: 'Supply Chain Attack',
        severity: 'critical',
        description: `Suspicious third-party integration activity detected`
    };
  }

  // 13. Compliance
  if (isFeatureEnabled('complianceDetection') && detectComplianceViolation(event)) {
      return {
          type: 'Compliance Violation',
          severity: 'medium',
          description: `Compliance policy violation detected (GDPR/HIPAA/PCI)`
      };
  }

  // 14. Threat Intelligence
  if (isFeatureEnabled('threatIntelligence')) {
      const threatCheck = checkThreatIntelligence(event);
      if (threatCheck.threat) {
          return {
              type: 'Known Threat',
              severity: 'critical',
              description: `Known threat detected: ${threatCheck.details}`
          };
      }
  }

  // 15. Zero Trust
  if (isFeatureEnabled('zeroTrustDetection') && detectZeroTrustViolation(event)) {
      return {
          type: 'Zero Trust Violation',
          severity: 'high',
          description: `Zero trust policy violation detected`
      };
  }

  // 16. Session Anomalies
  if (isFeatureEnabled('sessionAnomaliesDetection') && detectSessionAnomalies(event)) {
      return {
          type: 'Session Anomaly',
          severity: 'high',
          description: `Abnormal session behavior detected`
      };
  }

  // 17. Cryptographic Failures
  if (isFeatureEnabled('cryptographicValidation')) {
    const cryptoCheck = checkCryptographicFailures(event);
    if (!cryptoCheck.valid && cryptoCheck.issues.some(issue => issue.includes('plaintext password') || issue.includes('credit card'))) {
        return {
            type: 'Cryptographic Failure',
            severity: 'high',
            description: `Cleartext transmission of sensitive data detected`
        };
    }
    if (detectWeakEncryption(headers)) {
        return {
            type: 'Weak Encryption',
            severity: 'medium',
            description: `Weak encryption protocols detected`
        };
    }
  }

  // 18. Vulnerable Components
  if (isFeatureEnabled('vulnerableComponentsDetection')) {
    const vulnerabilities = detectVulnerableComponents(event);
    if (vulnerabilities.some(v => v.risk === 'critical' || v.risk === 'high')) {
        return {
            type: 'Vulnerable Component',
            severity: 'high',
            description: `Use of known vulnerable component detected`
        };
    }
    const cves = checkForCveReferences(event);
    if (cves.length > 0) {
        return {
            type: 'CVE Exploit Attempt',
            severity: 'critical',
            description: `Potential CVE exploitation attempt detected: ${cves.join(', ')}`
        };
    }
  }

  // 19. Authentication Failures
  if (isFeatureEnabled('authenticationValidation')) {
      const authIssues = detectAuthenticationFailures(event);
      const severeIssue = authIssues.find(issue => issue.severity === 'critical' || issue.severity === 'high');
      if (severeIssue) {
          return {
              type: 'Authentication Failure',
              severity: severeIssue.severity,
              description: severeIssue.description
          };
      }
  }

  // 20. Software Integrity
  if (isFeatureEnabled('softwareIntegrityValidation')) {
      const integrityIssues = checkSoftwareIntegrity(event);
      const severeIssue = integrityIssues.find(issue => issue.severity === 'critical' || issue.severity === 'high');
      if (severeIssue) {
          return {
              type: 'Integrity Violation',
              severity: severeIssue.severity,
              description: severeIssue.description
          };
      }
  }
  
  // 21. Access Control
  if (isFeatureEnabled('accessControlDetection')) {
      const userRole = (event as any).userRole || headers?.['x-user-role'];
      if (detectBrokenAccessControl(event, userRole)) {
        return {
            type: 'Broken Access Control',
            severity: 'high',
            description: 'Unauthorized access attempt detected'
        };
      }
  }

  // If no specific threat type was identified but isAnomaly returned true (logic mismatch fallback)
  // Ideally we should catch everything above.
  return {
    type: 'Security Anomaly',
    severity: 'medium',
    description: `Security threat detected in ${url}`
  };
}
