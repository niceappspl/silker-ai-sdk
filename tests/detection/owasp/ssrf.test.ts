import { detectSsrfAttack } from '../../../src/detection/owasp/ssrf';
import { VibeGuardEvent } from '../../../src/types';

describe('detectSsrfAttack', () => {
  const baseEvent: VibeGuardEvent = {
    method: 'GET',
    url: '/api/test',
    timestamp: Date.now()
  };

  describe('Localhost detection', () => {
    it('should detect localhost in URL', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'http://localhost:8080/api'
      };
      expect(detectSsrfAttack(event)).toBe(true);
    });

    it('should detect localhost case-insensitive', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'http://LOCALHOST:8080/api'
      };
      expect(detectSsrfAttack(event)).toBe(true);
    });
  });

  describe('Private IP addresses', () => {
    it('should detect 127.0.0.1', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'http://127.0.0.1:8080/api'
      };
      expect(detectSsrfAttack(event)).toBe(true);
    });

    it('should detect 0.0.0.0', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'http://0.0.0.0:8080/api'
      };
      expect(detectSsrfAttack(event)).toBe(true);
    });

    it('should detect 10.x.x.x range', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'http://10.0.0.1:8080/api'
      };
      expect(detectSsrfAttack(event)).toBe(true);
    });

    it('should detect 172.16-31.x.x range', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'http://172.16.0.1:8080/api'
      };
      expect(detectSsrfAttack(event)).toBe(true);
    });

    it('should detect 192.168.x.x range', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'http://192.168.1.1:8080/api'
      };
      expect(detectSsrfAttack(event)).toBe(true);
    });

    it('should detect 169.254.x.x range', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'http://169.254.1.1:8080/api'
      };
      expect(detectSsrfAttack(event)).toBe(true);
    });
  });

  describe('IPv6 addresses', () => {
    it('should detect ::1 (IPv6 localhost)', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'http://[::1]:8080/api'
      };
      expect(detectSsrfAttack(event)).toBe(true);
    });

    it('should detect [::1] format', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'http://[::1]/api'
      };
      expect(detectSsrfAttack(event)).toBe(true);
    });

    it('should detect fd00: (IPv6 private)', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'http://[fd00::1]/api'
      };
      expect(detectSsrfAttack(event)).toBe(true);
    });
  });

  describe('Cloud metadata endpoints', () => {
    it('should detect metadata.google', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'http://metadata.google.internal/computeMetadata/v1/'
      };
      expect(detectSsrfAttack(event)).toBe(true);
    });

    it('should detect 169.254.169.254 (AWS metadata)', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'http://169.254.169.254/latest/meta-data/'
      };
      expect(detectSsrfAttack(event)).toBe(true);
    });

    it('should detect internal keyword', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'http://internal.api.example.com'
      };
      expect(detectSsrfAttack(event)).toBe(true);
    });
  });

  describe('Legitimate URLs', () => {
    it('should allow public URLs', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'https://api.example.com/users'
      };
      expect(detectSsrfAttack(event)).toBe(false);
    });

    it('should allow relative URLs', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: '/api/users'
      };
      expect(detectSsrfAttack(event)).toBe(false);
    });

    it('should return false when URL is missing', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: ''
      };
      expect(detectSsrfAttack(event)).toBe(false);
    });
  });
});

