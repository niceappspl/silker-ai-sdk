import { isAnomaly, setGlobalOptions } from '../../src/detection/anomaly';
import { detectThreatType, setGlobalOptionsForThreat } from '../../src/detection/threatDetection';
import { applyProfile } from '../../src/config/profiles';
import { resolveSilkerOptions } from '../../src/config/env';
import { SilkerEvent } from '../../src/types';

function loginEvent(password: string): SilkerEvent {
  return {
    method: 'POST',
    url: '/api/login',
    payload: JSON.stringify({ username: 'admin', password }),
    ip: '10.0.0.1',
    timestamp: Date.now(),
    headers: {},
  };
}

describe('auth endpoint safe harbor', () => {
  beforeEach(() => {
    setGlobalOptions(null);
    setGlobalOptionsForThreat(null);
  });

  it('never blocks normal login attempts with all aggressive features enabled', () => {
    const base = applyProfile(resolveSilkerOptions({ profile: 'strict' }));
    const options = {
      ...base,
      features: {
        ...base.features,
        thirdPartyDetection: true,
        complianceDetection: true,
        dataLeakageDetection: { strategy: 'block' as const },
      },
    };
    setGlobalOptions(options);
    setGlobalOptionsForThreat(options);

    for (const password of ['test123', 'admin123', 'WrongPass9!', 'password', '123456']) {
      const event = loginEvent(password);
      expect(isAnomaly(event)).toBe(false);
    }
  });

  it('still blocks SQL injection on login endpoint', () => {
    setGlobalOptions(resolveSilkerOptions({}));
    setGlobalOptionsForThreat(resolveSilkerOptions({}));

    const event: SilkerEvent = {
      method: 'POST',
      url: '/api/login',
      payload: JSON.stringify({ username: "admin' OR '1'='1", password: 'x' }),
      ip: '10.0.0.1',
      timestamp: Date.now(),
      headers: {},
    };

    expect(isAnomaly(event)).toBe(true);
    expect(detectThreatType(event)?.type).toBe('SQL Injection');
  });

  it('blocks password fields on non-auth endpoints', () => {
    setGlobalOptions({ features: { dataLeakageDetection: { strategy: 'block' } } });
    setGlobalOptionsForThreat({ features: { dataLeakageDetection: { strategy: 'block' } } });

    const event: SilkerEvent = {
      method: 'POST',
      url: '/api/profile',
      payload: JSON.stringify({ password: 'SecretPass9!' }),
      ip: '10.0.0.1',
      timestamp: Date.now(),
      headers: {},
    };

    expect(isAnomaly(event)).toBe(true);
  });
});
