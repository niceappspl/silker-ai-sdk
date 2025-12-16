import { detectDataLeakage } from '../../src/detection/dataLeakage';

describe('detectDataLeakage', () => {
  describe('API key detection', () => {
    it('should detect Stripe API key in payload', () => {
      const payload = '{"apiKey":"sk_live_1234567890abcdef123456"}';
      const result = detectDataLeakage(payload);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.includes('API Key'))).toBe(true);
    });

    it('should detect JWT bearer token', () => {
      const payload = 'authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
      const result = detectDataLeakage(payload);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.includes('JWT Token'))).toBe(true);
    });

    it('should detect GitHub token', () => {
      const payload = '{"token":"ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"}';
      const result = detectDataLeakage(payload);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.includes('GitHub'))).toBe(true);
    });
  });

  describe('Secret detection', () => {
    it('should detect password in payload', () => {
      const payload = '{"password":"secret123456"}';
      const result = detectDataLeakage(payload);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.includes('Password'))).toBe(true);
    });

    it('should detect client secret', () => {
      const payload = '{"client_secret":"abc123def456ghi789jkl012"}';
      const result = detectDataLeakage(payload);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.includes('Secret'))).toBe(true);
    });

    it('should detect JWT token in payload', () => {
      const payload = '{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"}';
      const result = detectDataLeakage(payload);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.includes('JWT Token'))).toBe(true);
    });
  });

  describe('PII detection', () => {
    it('should detect SSN', () => {
      const payload = 'ssn=123-45-6789';
      const result = detectDataLeakage(payload);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.includes('SSN'))).toBe(true);
    });

    it('should detect credit card number', () => {
      const payload = 'card=4242424242424242';
      const result = detectDataLeakage(payload);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.includes('Credit Card'))).toBe(true);
    });

    it('should not detect email address (normal data)', () => {
      const payload = 'email=user@example.com';
      const result = detectDataLeakage(payload);
      expect(result.leaked).toBe(false);
    });
  });

  describe('Database credentials', () => {
    it('should detect MySQL connection string', () => {
      const payload = 'mysql://user:password@localhost:3306/database';
      const result = detectDataLeakage(payload);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.includes('Database Connection'))).toBe(true);
    });

    it('should detect PostgreSQL connection string', () => {
      const payload = 'postgresql://user:password@localhost:5432/database';
      const result = detectDataLeakage(payload);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.includes('Database Connection'))).toBe(true);
    });

    it('should detect MongoDB connection string', () => {
      const payload = 'mongodb://user:password@localhost:27017/database';
      const result = detectDataLeakage(payload);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.includes('Database Connection'))).toBe(true);
    });
  });

  describe('Response object detection', () => {
    it('should detect leaks in response object', () => {
      const response = {
        data: {
          api_key: 'sk_live_1234567890abcdefghijk',
          creditCard: '4242424242424242'
        }
      };
      const result = detectDataLeakage(undefined, response);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.includes('API Key') || f.includes('Credit Card'))).toBe(true);
    });

    it('should handle nested response objects', () => {
      const response = {
        user: {
          profile: {
            password: 'SuperSecret123!',
            token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature'
          }
        }
      };
      const result = detectDataLeakage(undefined, response);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.includes('Password') || f.includes('JWT'))).toBe(true);
    });
  });

  describe('No leaks', () => {
    it('should return no leaks for clean payload', () => {
      const payload = 'name=John&age=30&city=Warsaw';
      const result = detectDataLeakage(payload);
      expect(result.leaked).toBe(false);
      expect(result.findings.length).toBe(0);
    });

    it('should return no leaks when both payload and response are missing', () => {
      const result = detectDataLeakage();
      expect(result.leaked).toBe(false);
    });

    it('should limit findings to 10', () => {
      const payload = [
        '{"apiKey":"sk_live_1234567890abcdefgh1"}',
        '{"apiKey":"sk_live_1234567890abcdefgh2"}',
        '{"apiKey":"sk_live_1234567890abcdefgh3"}',
        '{"apiKey":"sk_live_1234567890abcdefgh4"}',
        '{"apiKey":"sk_live_1234567890abcdefgh5"}',
        '{"apiKey":"sk_live_1234567890abcdefgh6"}',
        '{"apiKey":"sk_live_1234567890abcdefgh7"}',
        '{"apiKey":"sk_live_1234567890abcdefgh8"}',
        '{"apiKey":"sk_live_1234567890abcdefgh9"}',
        '{"apiKey":"sk_live_1234567890abcdefgh10"}',
        '{"apiKey":"sk_live_1234567890abcdefgh11"}'
      ].join(' ');
      const result = detectDataLeakage(payload);
      expect(result.findings.length).toBeLessThanOrEqual(10);
    });
  });
});

