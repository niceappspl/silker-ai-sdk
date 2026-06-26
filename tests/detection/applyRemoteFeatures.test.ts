/**
 * Testy wzmocnionego applyRemoteFeatures: allowlista znanych kluczy + floor
 * (krytyczne detektory, których remote nie może wyłączyć).
 */
import { applyRemoteFeatures, setGlobalOptions, isAnomaly } from '../../src/detection/anomaly';
import { clearRateLimitState } from '../../src/detection/rateLimit';
import { SilkerEvent } from '../../src/types';

const sqliEvent = (): SilkerEvent => ({
  method: 'GET',
  url: "/search?q=' UNION SELECT password FROM users--",
  payload: "' UNION SELECT password FROM users--",
  ip: '198.51.100.5',
  timestamp: Date.now(),
  headers: {},
});

describe('applyRemoteFeatures hardening', () => {
  beforeEach(() => {
    clearRateLimitState();
    setGlobalOptions({ features: {} });
  });

  afterEach(() => {
    setGlobalOptions(null);
    clearRateLimitState();
  });

  it('applies known boolean feature keys from remote', () => {
    expect(isAnomaly(sqliEvent())).toBe(true);
    applyRemoteFeatures({ sqliDetection: false });
    expect(isAnomaly(sqliEvent())).toBe(false);
  });

  it('ignores unknown keys but still applies known ones', () => {
    applyRemoteFeatures({ totallyUnknownKey: false, sqliDetection: false } as any);
    // Known key applied (sqli off), unknown key ignored (no crash).
    expect(isAnomaly(sqliEvent())).toBe(false);
  });

  it('floor prevents remote from disabling a critical detector', () => {
    setGlobalOptions({ features: {}, remoteConfigFloor: ['sqliDetection'] });
    applyRemoteFeatures({ sqliDetection: false });
    // sqliDetection is in the floor - remote cannot turn it off.
    expect(isAnomaly(sqliEvent())).toBe(true);
  });

  it('floor still allows remote to ENABLE a feature', () => {
    setGlobalOptions({ features: { sqliDetection: false }, remoteConfigFloor: ['sqliDetection'] });
    expect(isAnomaly(sqliEvent())).toBe(false);
    applyRemoteFeatures({ sqliDetection: true });
    expect(isAnomaly(sqliEvent())).toBe(true);
  });
});
