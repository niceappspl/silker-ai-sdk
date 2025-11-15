import { SilkerEvent } from '../types';

/**
 * Sprawdza naruszenia zgodności z przepisami (GDPR, HIPAA).
 * Weryfikuje czy przetwarzanie danych osobowych ma odpowiednie zgody i autoryzacje.
 * @param event - Zdarzenie do sprawdzenia
 * @returns Obiekt z flagą naruszenia i listą znalezionych problemów
 */
export function checkComplianceViolations(event: SilkerEvent): { violation: boolean; issues: string[] } {
  const issues: string[] = [];
  const payload = event.payload || '';

  const urlLower = event.url.toLowerCase();
  const payloadLower = payload ? payload.toLowerCase() : '';
  if (urlLower.includes('delete') || urlLower.includes('erase') || urlLower.includes('forget') ||
      (payloadLower && (payloadLower.includes('delete') || payloadLower.includes('erase') || payloadLower.includes('forget')))) {
    const retentionHeaders = ['x-data-retention', 'data-retention-policy'];
    const hasRetentionPolicy = retentionHeaders.some(header => {
      const headerLower = header.toLowerCase();
      return event.headers?.[header] || 
             event.headers?.[headerLower] || 
             Object.keys(event.headers || {}).some(k => k.toLowerCase() === headerLower);
    });

    if (!hasRetentionPolicy) {
      issues.push('GDPR: Data deletion request without retention policy check');
    }
  }

  if (payload) {
    const piiPatterns = [
      /\b\d{3}-\d{2}-\d{4}\b/g,
      /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      /\b\d{10,15}\b/g,
      /\b\d{4}-\d{2}-\d{2}\b/g,
    ];

    let piiFound = false;
    for (const pattern of piiPatterns) {
      if (pattern.test(payload)) {
        piiFound = true;
        break;
      }
    }

    if (piiFound) {
      const consentHeaders = [
        'x-gdpr-consent', 'gdpr-consent', 'consent-id',
        'x-data-processing-consent', 'data-consent'
      ];

      const hasConsent = consentHeaders.some(header =>
        event.headers?.[header] || event.headers?.[header.toLowerCase()]
      );

      if (!hasConsent) {
        issues.push('GDPR: PII data processed without explicit consent');
      }
    }

  }

  if (payload.includes('medical') || payload.includes('health') || payload.includes('diagnosis')) {
    const hipaaHeaders = [
      'x-hipaa-authorization', 'hipaa-consent', 'medical-consent',
      'health-data-authorization', 'phi-consent'
    ];

    const hasHipaaAuth = hipaaHeaders.some(header =>
      event.headers?.[header] || event.headers?.[header.toLowerCase()]
    );

    if (!hasHipaaAuth) {
      issues.push('HIPAA: Protected health information processed without authorization');
    }

    if (!event.url.startsWith('https://')) {
      issues.push('HIPAA: Health data transmitted without TLS encryption');
    }
  }

  if (payload.length > 1000 && event.method === 'POST') {
    const classificationHeaders = [
      'x-data-classification', 'data-sensitivity', 'content-classification'
    ];

    const hasClassification = classificationHeaders.some(header =>
      event.headers?.[header] || event.headers?.[header.toLowerCase()]
    );

    if (!hasClassification) {
      issues.push('Compliance: Large data transfer without classification header');
    }
  }

  return { violation: issues.length > 0, issues };
}

/**
 * Wykrywa krytyczne naruszenia zgodności z przepisami.
 * @param event - Zdarzenie do sprawdzenia
 * @returns true jeśli wykryto krytyczne naruszenie zgodności, false w przeciwnym razie
 */
export function detectComplianceViolation(event: SilkerEvent): boolean {
  const complianceCheck = checkComplianceViolations(event);

  if (complianceCheck.violation) {
    const criticalViolations = complianceCheck.issues.filter(issue =>
      issue.includes('PII data processed without explicit consent') ||
      issue.includes('Protected health information processed without authorization')
    );

    return criticalViolations.length > 0;
  }

  return false;
}

