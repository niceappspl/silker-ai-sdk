import { CONFIG_PROFILES, applyProfile, deepMerge } from '../../src/config/profiles';
import { SilkerOptions } from '../../src/types';

describe('Configuration Profiles', () => {
  describe('CONFIG_PROFILES', () => {
    it('should have strict profile', () => {
      const profile = CONFIG_PROFILES['strict'];
      expect(profile).toBeDefined();
      expect(profile.features.promptInjectionDetection).toBe(true);
      expect(profile.features.dataLeakageDetection).toEqual({ strategy: 'block' });
      expect(profile.features.zeroTrustDetection).toBe(true);
      expect(profile.features.auditLogging).toBe(true);
    });

    it('should have saas profile with redact strategy', () => {
      const profile = CONFIG_PROFILES['saas'];
      expect(profile).toBeDefined();
      expect(profile.features.promptInjectionDetection).toBe(true);
      expect(profile.features.dataLeakageDetection).toEqual({ strategy: 'redact' });
      expect(profile.features.rateLimit).toBe(true);
    });

    it('should have audit profile with monitor strategy', () => {
      const profile = CONFIG_PROFILES['audit'];
      expect(profile).toBeDefined();
      expect(profile.features.dataLeakageDetection).toEqual({ strategy: 'monitor' });
      expect(profile.features.auditLogging).toBe(true);
      expect(profile.features.disableLegacySecurity).toBe(true);
    });
  });

  describe('applyProfile', () => {
    it('should apply saas profile defaults', () => {
      const options: SilkerOptions = {
        apiKey: 'sk_test_1234567890123456789012345678901234',
        profile: 'saas',
      };

      const result = applyProfile(options);

      expect(result.features?.promptInjectionDetection).toBe(true);
      expect(result.features?.dataLeakageDetection).toEqual({ strategy: 'redact' });
      expect(result.features?.rateLimit).toBe(true);
    });

    it('should allow user overrides on top of profile', () => {
      const options: SilkerOptions = {
        apiKey: 'sk_test_1234567890123456789012345678901234',
        profile: 'saas',
        features: {
          rateLimit: false,
        },
      };

      const result = applyProfile(options);

      expect(result.features?.promptInjectionDetection).toBe(true);
      expect(result.features?.rateLimit).toBe(false);
    });

    it('should return unchanged options if no profile specified', () => {
      const options: SilkerOptions = {
        apiKey: 'sk_test_1234567890123456789012345678901234',
        features: {
          rateLimit: true,
        },
      };

      const result = applyProfile(options);

      expect(result).toEqual(options);
    });

    it('should apply strict profile correctly', () => {
      const options: SilkerOptions = {
        apiKey: 'sk_test_1234567890123456789012345678901234',
        profile: 'strict',
      };

      const result = applyProfile(options);

      expect(result.features?.dataLeakageDetection).toEqual({ strategy: 'block' });
      expect(result.features?.zeroTrustDetection).toBe(true);
      expect(result.features?.ipBanning).toBe(true);
    });

    it('should apply audit profile correctly', () => {
      const options: SilkerOptions = {
        apiKey: 'sk_test_1234567890123456789012345678901234',
        profile: 'audit',
      };

      const result = applyProfile(options);

      expect(result.features?.dataLeakageDetection).toEqual({ strategy: 'monitor' });
      expect(result.features?.disableLegacySecurity).toBe(true);
      expect(result.features?.rateLimit).toBe(false);
    });
  });

  describe('deepMerge', () => {
    it('should merge nested objects', () => {
      const target = { a: 1, b: { c: 2, d: 3 } };
      const source = { b: { c: 5 } };

      const result = deepMerge(target, source);

      expect(result.a).toBe(1);
      expect(result.b.c).toBe(5);
      expect(result.b.d).toBe(3);
    });

    it('should override primitive values', () => {
      const target = { a: 1, b: 2 };
      const source = { a: 10 };

      const result = deepMerge(target, source);

      expect(result.a).toBe(10);
      expect(result.b).toBe(2);
    });

    it('should not mutate original objects', () => {
      const target = { a: 1, b: { c: 2 } };
      const source = { b: { c: 5 } };

      deepMerge(target, source);

      expect(target.b.c).toBe(2);
    });
  });
});
