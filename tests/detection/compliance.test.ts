import { checkComplianceViolations, detectComplianceViolation } from '../../src/detection/compliance';
import { SilkerEvent } from '../../src/types';

describe('checkComplianceViolations', () => {
  const baseEvent: SilkerEvent = {
    method: 'POST',
    url: '/api/test',
    timestamp: Date.now()
  };

  describe('GDPR violations', () => {
    it('should detect PII without consent', () => {
      const event: SilkerEvent = {
        ...baseEvent,
        payload: JSON.stringify({ email: 'user@example.com', name: 'John Doe' }),
        headers: {}
      };
      const result = checkComplianceViolations(event);
      expect(result.violation).toBe(true);
      expect(result.issues).toContain('GDPR: PII data processed without explicit consent');
    });

    it('should allow PII with consent header', () => {
      const event: SilkerEvent = {
        ...baseEvent,
        payload: JSON.stringify({ email: 'user@example.com' }),
        headers: { 'x-gdpr-consent': 'true' }
      };
      const result = checkComplianceViolations(event);
      expect(result.issues).not.toContain('GDPR: PII data processed without explicit consent');
    });

    it('should detect SSN without consent', () => {
      const event: SilkerEvent = {
        ...baseEvent,
        payload: JSON.stringify({ ssn: '123-45-6789' }),
        headers: {}
      };
      const result = checkComplianceViolations(event);
      expect(result.violation).toBe(true);
      expect(result.issues).toContain('GDPR: PII data processed without explicit consent');
    });

    it('should detect credit card without consent', () => {
      const event: SilkerEvent = {
        ...baseEvent,
        payload: JSON.stringify({ card: '4111-1111-1111-1111' }),
        headers: {}
      };
      const result = checkComplianceViolations(event);
      expect(result.violation).toBe(true);
    });

    it('should detect data deletion without retention policy', () => {
      const event: SilkerEvent = {
        ...baseEvent,
        url: '/api/user/delete',
        headers: {}
      };
      const result = checkComplianceViolations(event);
      expect(result.violation).toBe(true);
      expect(result.issues).toContain('GDPR: Data deletion request without retention policy check');
    });

    it('should allow data deletion with retention policy', () => {
      const event: SilkerEvent = {
        ...baseEvent,
        url: '/api/user/delete',
        headers: { 'x-data-retention': '30-days' }
      };
      const result = checkComplianceViolations(event);
      expect(result.issues).not.toContain('GDPR: Data deletion request without retention policy check');
    });
  });

  describe('HIPAA violations', () => {
    it('should detect medical data without authorization', () => {
      const event: SilkerEvent = {
        ...baseEvent,
        payload: JSON.stringify({ diagnosis: 'diabetes', medical: 'data' }),
        headers: {}
      };
      const result = checkComplianceViolations(event);
      expect(result.violation).toBe(true);
      expect(result.issues).toContain('HIPAA: Protected health information processed without authorization');
    });

    it('should allow medical data with HIPAA authorization', () => {
      const event: SilkerEvent = {
        ...baseEvent,
        payload: JSON.stringify({ diagnosis: 'diabetes' }),
        headers: { 'x-hipaa-authorization': 'true' }
      };
      const result = checkComplianceViolations(event);
      expect(result.issues).not.toContain('HIPAA: Protected health information processed without authorization');
    });

    it('should detect health data without TLS', () => {
      const event: SilkerEvent = {
        ...baseEvent,
        url: 'http://api.example.com/health',
        payload: JSON.stringify({ health: 'data' }),
        headers: { 'x-hipaa-authorization': 'true' }
      };
      const result = checkComplianceViolations(event);
      expect(result.violation).toBe(true);
      expect(result.issues).toContain('HIPAA: Health data transmitted without TLS encryption');
    });

    it('should allow health data with HTTPS', () => {
      const event: SilkerEvent = {
        ...baseEvent,
        url: 'https://api.example.com/health',
        payload: JSON.stringify({ health: 'data' }),
        headers: { 'x-hipaa-authorization': 'true' }
      };
      const result = checkComplianceViolations(event);
      expect(result.issues).not.toContain('HIPAA: Health data transmitted without TLS encryption');
    });
  });

  describe('Data classification', () => {
    it('should detect large data transfer without classification', () => {
      const largePayload = 'x'.repeat(1001);
      const event: SilkerEvent = {
        ...baseEvent,
        method: 'POST',
        payload: largePayload,
        headers: {}
      };
      const result = checkComplianceViolations(event);
      expect(result.violation).toBe(true);
      expect(result.issues).toContain('Compliance: Large data transfer without classification header');
    });

    it('should allow large data transfer with classification', () => {
      const largePayload = 'x'.repeat(1001);
      const event: SilkerEvent = {
        ...baseEvent,
        method: 'POST',
        payload: largePayload,
        headers: { 'x-data-classification': 'confidential' }
      };
      const result = checkComplianceViolations(event);
      expect(result.issues).not.toContain('Compliance: Large data transfer without classification header');
    });

    it('should not check classification for GET requests', () => {
      const largePayload = 'x'.repeat(1001);
      const event: SilkerEvent = {
        ...baseEvent,
        method: 'GET',
        payload: largePayload,
        headers: {}
      };
      const result = checkComplianceViolations(event);
      expect(result.issues).not.toContain('Compliance: Large data transfer without classification header');
    });
  });

  describe('No violations', () => {
    it('should return no violations for clean request', () => {
      const event: SilkerEvent = {
        ...baseEvent,
        payload: JSON.stringify({ name: 'John', age: 30 }),
        headers: {}
      };
      const result = checkComplianceViolations(event);
      expect(result.violation).toBe(false);
    });

    it('should return no violations for empty payload', () => {
      const event: SilkerEvent = {
        ...baseEvent,
        headers: {}
      };
      const result = checkComplianceViolations(event);
      expect(result.violation).toBe(false);
    });
  });
});

describe('detectComplianceViolation', () => {
  const baseEvent: SilkerEvent = {
    method: 'POST',
    url: '/api/test',
    timestamp: Date.now()
  };

  it('should detect critical GDPR violation', () => {
    const event: SilkerEvent = {
      ...baseEvent,
      payload: JSON.stringify({ email: 'user@example.com' }),
      headers: {}
    };
    expect(detectComplianceViolation(event)).toBe(true);
  });

  it('should detect critical HIPAA violation', () => {
    const event: SilkerEvent = {
      ...baseEvent,
      payload: JSON.stringify({ medical: 'data' }),
      headers: {}
    };
    expect(detectComplianceViolation(event)).toBe(true);
  });

  it('should not detect non-critical violations', () => {
    const event: SilkerEvent = {
      ...baseEvent,
      payload: 'x'.repeat(1001),
      headers: {}
    };
    expect(detectComplianceViolation(event)).toBe(false);
  });

  it('should return false for compliant request', () => {
    const event: SilkerEvent = {
      ...baseEvent,
      payload: JSON.stringify({ name: 'John' }),
      headers: {}
    };
    expect(detectComplianceViolation(event)).toBe(false);
  });
});

