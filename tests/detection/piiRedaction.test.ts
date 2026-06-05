import { redactPii, redactJsonPayload } from '../../src/detection/piiRedaction';

describe('PII Redaction', () => {
  describe('redactPii', () => {
    it('should redact email addresses', () => {
      const payload = 'Contact me at john.doe@example.com for more info';
      const result = redactPii(payload);

      expect(result.originalFlagged).toBe(true);
      expect(result.redactedPayload).toBe('Contact me at [REDACTED_EMAIL] for more info');
      expect(result.redactedFields).toContain('email');
      expect(result.dataTypesDetected).toContain('email');
    });

    it('should redact multiple email addresses', () => {
      const payload = 'Send to alice@test.com and bob@company.org';
      const result = redactPii(payload);

      expect(result.redactedPayload).toBe('Send to [REDACTED_EMAIL] and [REDACTED_EMAIL]');
      expect(result.redactedFields).toContain('email');
    });

    it('should redact phone numbers with separators', () => {
      const payloads = [
        { input: 'Call me at 555-123-4567', expected: 'Call me at [REDACTED_PHONE]' },
        { input: 'Contact: +1-555-123-4567', expected: 'Contact: [REDACTED_PHONE]' },
        { input: 'Phone: 555.123.4567', expected: 'Phone: [REDACTED_PHONE]' },
        { input: 'Mobile: 555 123 4567', expected: 'Mobile: [REDACTED_PHONE]' },
      ];

      payloads.forEach(({ input, expected }) => {
        const result = redactPii(input);
        expect(result.redactedPayload).toBe(expected);
        expect(result.redactedFields).toContain('phone');
      });
    });

    it('should redact credit card numbers with Luhn validation', () => {
      const payload = 'Card: 4532015112830366';
      const result = redactPii(payload);

      expect(result.originalFlagged).toBe(true);
      expect(result.redactedPayload).toContain('[REDACTED_CREDIT_CARD]');
      expect(result.redactedFields).toContain('credit_card');
    });

    it('should not redact invalid credit card numbers', () => {
      const payload = 'Number: 1234567890123456';
      const result = redactPii(payload);

      expect(result.redactedPayload).toBe(payload);
      expect(result.redactedFields).not.toContain('credit_card');
    });

    it('should redact SSN', () => {
      const payload = 'SSN: 123-45-6789';
      const result = redactPii(payload);

      expect(result.redactedPayload).toBe('SSN: [REDACTED_SSN]');
      expect(result.redactedFields).toContain('ssn');
      expect(result.dataTypesDetected).toContain('ssn');
    });

    it('should redact valid PESEL numbers', () => {
      const payload = 'PESEL: 44051401458';
      const result = redactPii(payload);

      expect(result.redactedPayload).toBe('PESEL: [REDACTED_PESEL]');
      expect(result.redactedFields).toContain('pesel');
    });

    it('should not redact invalid PESEL numbers', () => {
      const payload = 'Number: 12345678901';
      const result = redactPii(payload);

      expect(result.redactedPayload).toBe(payload);
      expect(result.redactedFields).not.toContain('pesel');
    });

    it('should redact multiple PII types', () => {
      const payload = 'Email: user@test.com, Phone: 555-123-4567, SSN: 123-45-6789';
      const result = redactPii(payload);

      expect(result.originalFlagged).toBe(true);
      expect(result.redactedPayload).toContain('[REDACTED_EMAIL]');
      expect(result.redactedPayload).toContain('[REDACTED_PHONE]');
      expect(result.redactedPayload).toContain('[REDACTED_SSN]');
      expect(result.dataTypesDetected).toContain('email');
      expect(result.dataTypesDetected).toContain('phone');
      expect(result.dataTypesDetected).toContain('ssn');
    });

    it('should return unchanged payload when no PII found', () => {
      const payload = 'This is a normal message without any personal data';
      const result = redactPii(payload);

      expect(result.originalFlagged).toBe(false);
      expect(result.redactedPayload).toBe(payload);
      expect(result.redactedFields).toHaveLength(0);
    });

    it('should respect pattern configuration', () => {
      const payload = 'Email: user@test.com, Phone: 555-123-4567';
      const result = redactPii(payload, { email: true, phone: false });

      expect(result.redactedPayload).toContain('[REDACTED_EMAIL]');
      expect(result.redactedPayload).toContain('555-123-4567');
    });
  });

  describe('redactJsonPayload', () => {
    it('should redact PII in JSON object', () => {
      const body = {
        name: 'John Doe',
        email: 'john@example.com',
        message: 'Hello world',
      };

      const { redactedBody, result } = redactJsonPayload(body);

      expect(result.originalFlagged).toBe(true);
      expect(redactedBody.email).toBe('[REDACTED_EMAIL]');
      expect(redactedBody.name).toBe('John Doe');
      expect(redactedBody.message).toBe('Hello world');
    });

    it('should handle nested objects', () => {
      const body = {
        user: {
          contact: {
            email: 'nested@example.com',
            phone: '555-123-4567',
          },
        },
      };

      const { redactedBody, result } = redactJsonPayload(body);

      expect(result.originalFlagged).toBe(true);
      expect(redactedBody.user.contact.email).toBe('[REDACTED_EMAIL]');
      expect(redactedBody.user.contact.phone).toBe('[REDACTED_PHONE]');
    });

    it('should handle string payload', () => {
      const body = '{"email": "test@example.com"}';

      const { redactedBody, result } = redactJsonPayload(body);

      expect(result.originalFlagged).toBe(true);
      expect(redactedBody.email).toBe('[REDACTED_EMAIL]');
    });

    it('should handle null/undefined payload', () => {
      const { redactedBody, result } = redactJsonPayload(null);

      expect(result.originalFlagged).toBe(false);
      expect(redactedBody).toBeNull();
    });

    it('should handle empty object', () => {
      const { redactedBody, result } = redactJsonPayload({});

      expect(result.originalFlagged).toBe(false);
      expect(redactedBody).toEqual({});
    });
  });
});
