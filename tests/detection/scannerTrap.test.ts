import { detectScannerTrap } from '../../src/detection/scannerTrap';
import { isAnomaly, setGlobalOptions } from '../../src/detection/anomaly';
import { detectThreatType, setGlobalOptionsForThreat } from '../../src/detection/threatDetection';
import { clearRateLimitState, isIpBanned } from '../../src/detection/rateLimit';
import { SilkerEvent } from '../../src/types';

describe('Scanner trap (honeypot paths)', () => {
  beforeEach(() => {
    clearRateLimitState();
    setGlobalOptions(null);
    setGlobalOptionsForThreat(null);
  });

  afterEach(() => {
    setGlobalOptions(null);
    setGlobalOptionsForThreat(null);
  });

  describe('detectScannerTrap', () => {
    it.each([
      ['/.env', 'env-probe'],
      ['/.env.production', 'env-probe'],
      ['/.git/config', 'vcs-probe'],
      ['/.aws/credentials', 'env-probe'],
      ['/.ssh/id_rsa', 'env-probe'],
      ['/wp-login.php', 'cms-probe'],
      ['/wp-admin/setup-config.php', 'cms-probe'],
      ['/xmlrpc.php', 'cms-probe'],
      ['/phpmyadmin/index.php', 'admin-probe'],
      ['/cgi-bin/test.cgi', 'admin-probe'],
      ['/actuator/env', 'admin-probe'],
      ['/backup.sql', 'backup-probe'],
      ['/api/v1/.env', 'env-probe'],
      ['/uploads/shell.php', 'cms-probe'],
    ])('detects %s as %s', (path, category) => {
      const result = detectScannerTrap(path);
      expect(result.detected).toBe(true);
      expect(result.category).toBe(category);
    });

    it('detects trap paths in full URLs and ignores query strings', () => {
      expect(detectScannerTrap('https://example.com/.env?x=1').detected).toBe(true);
      expect(detectScannerTrap('/wp-login.php?redirect_to=admin').detected).toBe(true);
    });

    it('is case-insensitive', () => {
      expect(detectScannerTrap('/WP-LOGIN.PHP').detected).toBe(true);
      expect(detectScannerTrap('/.ENV').detected).toBe(true);
    });

    it.each([
      '/',
      '/api/users',
      '/api/chat',
      '/.well-known/security.txt',
      '/admin',
      '/environment',
      '/blog/wordpress-vs-nextjs',
      '/docs/configuration',
      '/static/env-banner.png',
    ])('does NOT flag legitimate path %s', (path) => {
      expect(detectScannerTrap(path).detected).toBe(false);
    });

    it('returns not-detected for empty url', () => {
      expect(detectScannerTrap('').detected).toBe(false);
    });
  });

  describe('isAnomaly integration', () => {
    const trapEvent = (url: string, ip: string): SilkerEvent => ({
      method: 'GET',
      url,
      ip,
      timestamp: Date.now(),
    });

    it('flags trap hits as anomalies by default (no config)', () => {
      expect(isAnomaly(trapEvent('/.env', '10.40.0.1'))).toBe(true);
      expect(isAnomaly(trapEvent('/wp-login.php', '10.40.0.2'))).toBe(true);
    });

    it('auto-bans the scanner IP when ipBanning is enabled (default)', () => {
      const ip = '10.40.0.3';
      expect(isIpBanned(ip)).toBe(false);
      expect(isAnomaly(trapEvent('/.git/config', ip))).toBe(true);
      expect(isIpBanned(ip)).toBe(true);
    });

    it('does NOT ban when ipBanning is disabled', () => {
      setGlobalOptions({ features: { ipBanning: false } });
      const ip = '10.40.0.4';
      expect(isAnomaly(trapEvent('/.env', ip))).toBe(true);
      expect(isIpBanned(ip)).toBe(false);
    });

    it('can be disabled via scannerTrapDetection: false', () => {
      setGlobalOptions({ features: { scannerTrapDetection: false } });
      expect(isAnomaly(trapEvent('/.env', '10.40.0.5'))).toBe(false);
    });
  });

  describe('detectThreatType classification', () => {
    it('classifies trap hits as Scanner Probe (high severity)', () => {
      const event: SilkerEvent = {
        method: 'GET',
        url: '/.env',
        ip: '10.40.1.1',
        timestamp: Date.now(),
      };
      const threat = detectThreatType(event);
      expect(threat?.type).toBe('Scanner Probe');
      expect(threat?.severity).toBe('high');
      expect(threat?.description).toContain('env-probe');
    });

    it('does not classify when feature disabled', () => {
      setGlobalOptionsForThreat({ features: { scannerTrapDetection: false } });
      const event: SilkerEvent = {
        method: 'GET',
        url: '/.env',
        ip: '10.40.1.2',
        timestamp: Date.now(),
      };
      expect(detectThreatType(event)?.type).not.toBe('Scanner Probe');
    });
  });
});
