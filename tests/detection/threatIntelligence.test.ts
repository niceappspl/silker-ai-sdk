import { checkThreatIntelligence } from '../../src/detection/threatIntelligence';
import { VibeGuardEvent } from '../../src/types';

describe('checkThreatIntelligence', () => {
  const baseEvent: VibeGuardEvent = {
    method: 'GET',
    url: '/api/test',
    timestamp: Date.now()
  };

  describe('Known malicious IPs', () => {
    it('should detect known malicious IP', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        ip: '185.220.101.1'
      };
      const result = checkThreatIntelligence(event);
      expect(result.threat).toBe(true);
      expect(result.details).toContain('IP 185.220.101.1 flagged in threat intelligence');
    });

    it('should detect another known malicious IP', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        ip: '185.220.101.2'
      };
      const result = checkThreatIntelligence(event);
      expect(result.threat).toBe(true);
    });

    it('should not detect legitimate IP', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        ip: '192.168.1.1'
      };
      const result = checkThreatIntelligence(event);
      expect(result.threat).toBe(false);
    });

    it('should handle missing IP', () => {
      const event: VibeGuardEvent = {
        ...baseEvent
      };
      const result = checkThreatIntelligence(event);
      expect(result.threat).toBe(false);
    });
  });

  describe('Malicious domains', () => {
    it('should detect malicious domain in URL', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'https://malicious-site.com/api'
      };
      const result = checkThreatIntelligence(event);
      expect(result.threat).toBe(true);
      expect(result.details).toContain('Domain malicious-site.com flagged as malicious');
    });

    it('should detect phishing domain', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'https://phishing-domain.net/login'
      };
      const result = checkThreatIntelligence(event);
      expect(result.threat).toBe(true);
    });

    it('should detect malware host', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'http://malware-host.org/download'
      };
      const result = checkThreatIntelligence(event);
      expect(result.threat).toBe(true);
    });

    it('should not detect legitimate domain', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'https://example.com/api'
      };
      const result = checkThreatIntelligence(event);
      expect(result.threat).toBe(false);
    });

    it('should handle URL without protocol', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'malicious-site.com/api'
      };
      const result = checkThreatIntelligence(event);
      expect(result.threat).toBe(true);
    });

    it('should handle invalid URL gracefully', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        url: 'not-a-valid-url'
      };
      const result = checkThreatIntelligence(event);
      expect(result.threat).toBe(false);
    });
  });

  describe('Security scanners', () => {
    it('should detect sqlmap user agent', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        userAgent: 'sqlmap/1.0'
      };
      const result = checkThreatIntelligence(event);
      expect(result.threat).toBe(true);
      expect(result.details.some(d => d.includes('sqlmap'))).toBe(true);
    });

    it('should detect nikto scanner', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        userAgent: 'Mozilla/5.0 (compatible; nikto/2.1.6)'
      };
      const result = checkThreatIntelligence(event);
      expect(result.threat).toBe(true);
    });

    it('should detect dirbuster', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        userAgent: 'dirbuster/1.0'
      };
      const result = checkThreatIntelligence(event);
      expect(result.threat).toBe(true);
    });

    it('should detect gobuster', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        userAgent: 'gobuster/3.0'
      };
      const result = checkThreatIntelligence(event);
      expect(result.threat).toBe(true);
    });

    it('should detect acunetix', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        userAgent: 'Acunetix-Web-Security-Scanner'
      };
      const result = checkThreatIntelligence(event);
      expect(result.threat).toBe(true);
    });

    it('should detect openvas', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        userAgent: 'OpenVAS'
      };
      const result = checkThreatIntelligence(event);
      expect(result.threat).toBe(true);
    });

    it('should not detect legitimate user agent', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      };
      const result = checkThreatIntelligence(event);
      expect(result.threat).toBe(false);
    });

    it('should handle case-insensitive scanner detection', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        userAgent: 'SQLMAP/1.0'
      };
      const result = checkThreatIntelligence(event);
      expect(result.threat).toBe(true);
    });
  });

  describe('Multiple threats', () => {
    it('should detect multiple threats', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        ip: '185.220.101.1',
        url: 'https://malicious-site.com/api',
        userAgent: 'sqlmap/1.0'
      };
      const result = checkThreatIntelligence(event);
      expect(result.threat).toBe(true);
      expect(result.details.length).toBeGreaterThan(1);
    });
  });
});

