import { sanitizeSensitiveData } from '../../src/cloud/sanitization';

describe('sanitizeSensitiveData', () => {
  describe('String sanitization', () => {
    it('should mask password in JSON string', () => {
      const input = '{"password":"secret123"}';
      const result = sanitizeSensitiveData(input);
      expect(result).toContain('***MASKED***');
      expect(result).not.toContain('secret123');
    });

    it('should mask api_key in JSON string', () => {
      const input = '{"api_key":"sk-1234567890abcdef"}';
      const result = sanitizeSensitiveData(input);
      expect(result).toContain('***MASKED***');
      expect(result).not.toContain('sk-1234567890abcdef');
    });

    it('should mask token in JSON string', () => {
      const input = '{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}';
      const result = sanitizeSensitiveData(input);
      expect(result).toContain('***MASKED***');
    });

    it('should mask multiple sensitive fields', () => {
      const input = '{"password":"secret","api_key":"sk-123","token":"abc123"}';
      const result = sanitizeSensitiveData(input);
      expect(result).not.toContain('secret');
      expect(result).not.toContain('sk-123');
      expect(result).not.toContain('abc123');
    });

    it('should not mask short values', () => {
      const input = '{"password":"abc"}';
      const result = sanitizeSensitiveData(input);
      expect(result).toContain('abc');
    });

    it('should handle empty string', () => {
      const result = sanitizeSensitiveData('');
      expect(result).toBe('');
    });
  });

  describe('Object sanitization', () => {
    it('should mask password in object', () => {
      const input = {
        username: 'user',
        password: 'secret123'
      };
      const result = sanitizeSensitiveData(input);
      expect(result.password).toBe('***MASKED***');
      expect(result.username).toBe('user');
    });

    it('should mask nested sensitive data', () => {
      const input = {
        user: {
          email: 'user@example.com',
          password: 'secret',
          api_key: 'sk-123'
        }
      };
      const result = sanitizeSensitiveData(input);
      expect(result.user.password).toBe('***MASKED***');
      expect(result.user.api_key).toBe('***MASKED***');
      expect(result.user.email).toBe('***MASKED***');
    });

    it('should mask case-insensitive sensitive keys', () => {
      const input = {
        Password: 'secret',
        API_KEY: 'sk-123',
        Token: 'abc123'
      };
      const result = sanitizeSensitiveData(input);
      expect(result.Password).toBe('***MASKED***');
      expect(result.API_KEY).toBe('***MASKED***');
      expect(result.Token).toBe('***MASKED***');
    });

    it('should mask partial key matches', () => {
      const input = {
        user_password: 'secret',
        api_key_value: 'sk-123',
        auth_token: 'abc123'
      };
      const result = sanitizeSensitiveData(input);
      expect(result.user_password).toBe('***MASKED***');
      expect(result.api_key_value).toBe('***MASKED***');
      expect(result.auth_token).toBe('***MASKED***');
    });

    it('should handle empty object', () => {
      const result = sanitizeSensitiveData({});
      expect(result).toEqual({});
    });

    it('should preserve non-sensitive data', () => {
      const input = {
        name: 'John Doe',
        age: 30,
        city: 'Warsaw'
      };
      const result = sanitizeSensitiveData(input);
      expect(result.name).toBe('John Doe');
      expect(result.age).toBe(30);
      expect(result.city).toBe('Warsaw');
    });
  });

  describe('Array sanitization', () => {
    it('should sanitize array of objects', () => {
      const input = [
        { username: 'user1', password: 'secret1' },
        { username: 'user2', password: 'secret2' }
      ];
      const result = sanitizeSensitiveData(input);
      expect(result[0].password).toBe('***MASKED***');
      expect(result[1].password).toBe('***MASKED***');
      expect(result[0].username).toBe('user1');
    });

    it('should handle empty array', () => {
      const result = sanitizeSensitiveData([]);
      expect(result).toEqual([]);
    });
  });

  describe('Edge cases', () => {
    it('should handle null', () => {
      const result = sanitizeSensitiveData(null);
      expect(result).toBeNull();
    });

    it('should handle undefined', () => {
      const result = sanitizeSensitiveData(undefined);
      expect(result).toBeUndefined();
    });

    it('should handle number', () => {
      const result = sanitizeSensitiveData(123);
      expect(result).toBe(123);
    });

    it('should handle boolean', () => {
      const result = sanitizeSensitiveData(true);
      expect(result).toBe(true);
    });

    it('should mask database connection strings', () => {
      const input = {
        database_url: 'postgresql://user:pass@localhost/db',
        db_url: 'mysql://user:pass@localhost/db',
        connection_string: 'mongodb://user:pass@localhost/db'
      };
      const result = sanitizeSensitiveData(input);
      expect(result.database_url).toBe('***MASKED***');
      expect(result.db_url).toBe('***MASKED***');
      expect(result.connection_string).toBe('***MASKED***');
    });

    it('should mask PII fields', () => {
      const input = {
        ssn: '123-45-6789',
        credit_card: '4111111111111111',
        email: 'user@example.com',
        phone: '1234567890'
      };
      const result = sanitizeSensitiveData(input);
      expect(result.ssn).toBe('***MASKED***');
      expect(result.credit_card).toBe('***MASKED***');
      expect(result.email).toBe('***MASKED***');
      expect(result.phone).toBe('***MASKED***');
    });
  });
});

