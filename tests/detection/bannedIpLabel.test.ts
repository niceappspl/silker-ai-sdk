import { detectThreatType, setGlobalOptionsForThreat } from '../../src/detection/threatDetection';
import { clearRateLimitState, banIp, setRateLimitConfig } from '../../src/detection/rateLimit';
import { SilkerEvent } from '../../src/types';

/**
 * Regression: an already-banned IP must be reported as "Banned IP Activity",
 * NOT mislabeled as "Rate Limiting" (checkRateLimit returns true for both).
 */
describe('detectThreatType - banned IP vs rate limit labeling', () => {
  beforeEach(() => {
    clearRateLimitState();
    setRateLimitConfig({ maxRequests: 5, windowMs: 60000, banDurationMs: 300000 });
    setGlobalOptionsForThreat({ features: { rateLimit: true, ipBanning: true } });
  });

  afterEach(() => {
    clearRateLimitState();
    setGlobalOptionsForThreat(null);
  });

  it('labels an already-banned IP as "Banned IP Activity"', () => {
    const ip = '203.0.113.10';
    banIp(ip);
    const event: SilkerEvent = { method: 'GET', url: '/api/anything', ip, timestamp: Date.now() };
    expect(detectThreatType(event)?.type).toBe('Banned IP Activity');
  });

  it('labels the request that trips the limit as "Rate Limiting"', () => {
    const ip = '203.0.113.20';
    const event: SilkerEvent = { method: 'GET', url: '/api/anything', ip, timestamp: Date.now() };
    // Calls 1-5 stay within the 5/min limit; the 6th call trips it.
    let last;
    for (let i = 0; i < 6; i++) last = detectThreatType({ ...event, timestamp: Date.now() });
    expect(last?.type).toBe('Rate Limiting');
  });
});
