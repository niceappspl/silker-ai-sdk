import { isAnomaly, setGlobalOptions, getDataLeakageConfig, DEFAULT_FEATURES } from '../../src/detection/anomaly';
import { clearRateLimitState } from '../../src/detection/rateLimit';
import { SilkerEvent } from '../../src/types';

describe('Feature defaults', () => {
  beforeEach(() => {
    clearRateLimitState();
    setGlobalOptions(null);
  });

  afterEach(() => {
    setGlobalOptions(null);
  });

  describe('DEFAULT_FEATURES map', () => {
    it('should keep core detectors ON by default', () => {
      expect(DEFAULT_FEATURES.sqliDetection).toBe(true);
      expect(DEFAULT_FEATURES.xssDetection).toBe(true);
      expect(DEFAULT_FEATURES.pathTraversalDetection).toBe(true);
      expect(DEFAULT_FEATURES.promptInjectionDetection).toBe(true);
      expect(DEFAULT_FEATURES.rateLimit).toBe(true);
      expect(DEFAULT_FEATURES.dataLeakageDetection).toBe(true);
      expect(DEFAULT_FEATURES.fileUploadDetection).toBe(true);
    });

    it('should keep noisy detectors OFF by default (opt-in)', () => {
      expect(DEFAULT_FEATURES.zeroTrustDetection).toBe(false);
      expect(DEFAULT_FEATURES.csrfDetection).toBe(false);
      expect(DEFAULT_FEATURES.accessControlDetection).toBe(false);
      expect(DEFAULT_FEATURES.vulnerableComponentsDetection).toBe(false);
      expect(DEFAULT_FEATURES.thirdPartyDetection).toBe(false);
      expect(DEFAULT_FEATURES.complianceDetection).toBe(false);
      expect(DEFAULT_FEATURES.threatIntelligence).toBe(false);
      expect(DEFAULT_FEATURES.sessionAnomaliesDetection).toBe(false);
      expect(DEFAULT_FEATURES.ssrfDetection).toBe(false);
      expect(DEFAULT_FEATURES.idorDetection).toBe(false);
      expect(DEFAULT_FEATURES.hostHeaderInjectionDetection).toBe(false);
      expect(DEFAULT_FEATURES.authenticationValidation).toBe(false);
      expect(DEFAULT_FEATURES.softwareIntegrityValidation).toBe(false);
      expect(DEFAULT_FEATURES.cryptographicValidation).toBe(false);
    });
  });

  describe('isAnomaly with defaults', () => {
    it('should detect SQLi without any configuration (default ON)', () => {
      const event: SilkerEvent = {
        method: 'POST',
        url: '/api/login',
        payload: "'; DROP TABLE users; --",
        ip: '10.10.10.1',
        timestamp: Date.now()
      };
      expect(isAnomaly(event)).toBe(true);
    });

    it('should NOT flag internal URLs as SSRF by default (opt-in)', () => {
      const event: SilkerEvent = {
        method: 'GET',
        url: 'http://localhost:8080/internal',
        ip: '10.10.10.2',
        timestamp: Date.now()
      };
      expect(isAnomaly(event)).toBe(false);
    });

    it('should flag internal URLs as SSRF when explicitly enabled', () => {
      setGlobalOptions({ features: { ssrfDetection: true } });
      const event: SilkerEvent = {
        method: 'GET',
        url: 'http://localhost:8080/internal',
        ip: '10.10.10.3',
        timestamp: Date.now()
      };
      expect(isAnomaly(event)).toBe(true);
    });
  });

  describe('getDataLeakageConfig', () => {
    it('should return default block strategy when not configured', () => {
      setGlobalOptions(null);
      expect(getDataLeakageConfig()).toEqual({ strategy: 'block' });
    });

    it('should return default block strategy when set to true', () => {
      setGlobalOptions({ features: { dataLeakageDetection: true } });
      expect(getDataLeakageConfig()).toEqual({ strategy: 'block' });
    });

    it('should return null (disabled) when explicitly set to false', () => {
      setGlobalOptions({ features: { dataLeakageDetection: false } });
      expect(getDataLeakageConfig()).toBeNull();
    });

    it('should return the config object when provided', () => {
      setGlobalOptions({ features: { dataLeakageDetection: { strategy: 'redact' } } });
      expect(getDataLeakageConfig()).toEqual({ strategy: 'redact' });
    });
  });
});
