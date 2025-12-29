import { checkRateLimit, clearRateLimitState, banIp, unbanIp, isIpBanned } from '../../src/detection/rateLimit';
import { SilkerEvent } from '../../src/types';

describe('checkRateLimit', () => {
  const baseEvent: SilkerEvent = {
    method: 'GET',
    url: '/api/test',
    timestamp: Date.now()
  };

  beforeEach(() => {
    clearRateLimitState();
  });

  it('should return false when IP is missing', () => {
    const event: SilkerEvent = {
      ...baseEvent,
      ip: undefined
    };
    expect(checkRateLimit(event)).toBe(false);
  });

  it('should allow requests within rate limit', () => {
    const event: SilkerEvent = {
      ...baseEvent,
      ip: '192.168.1.1'
    };

    for (let i = 0; i < 5; i++) {
      expect(checkRateLimit(event)).toBe(false);
    }
  });

  it('should block requests exceeding rate limit and ban IP', () => {
    const event: SilkerEvent = {
      ...baseEvent,
      ip: '192.168.1.1'
    };

    for (let i = 0; i < 5; i++) {
      checkRateLimit(event);
    }

    expect(checkRateLimit(event)).toBe(true);
    expect(isIpBanned('192.168.1.1')).toBe(true);
  });

  it('should reset rate limit after time window if not banned', async () => {
    jest.useFakeTimers();
    const startTime = Date.now();
    jest.setSystemTime(startTime);
    
    const event: SilkerEvent = {
      ...baseEvent,
      ip: '192.168.1.2',
      timestamp: startTime
    };

    // 5 requests is the limit
    for (let i = 0; i < 5; i++) {
      checkRateLimit({ ...event, timestamp: startTime + i });
    }

    // Advance time past window
    jest.advanceTimersByTime(61000);
    jest.setSystemTime(startTime + 61000);

    const newEvent: SilkerEvent = {
      ...baseEvent,
      ip: '192.168.1.2',
      timestamp: Date.now()
    };
    
    expect(checkRateLimit(newEvent)).toBe(false);
    jest.useRealTimers();
  });

  it('should stay blocked if IP is banned even after window reset', () => {
    jest.useFakeTimers();
    const startTime = Date.now();
    jest.setSystemTime(startTime);

    const event: SilkerEvent = {
      ...baseEvent,
      ip: '192.168.1.5'
    };

    // Force a ban
    for (let i = 0; i < 6; i++) {
      checkRateLimit(event);
    }
    expect(isIpBanned('192.168.1.5')).toBe(true);

    // Advance time past window but NOT past ban duration (5 min)
    jest.advanceTimersByTime(61000);
    jest.setSystemTime(startTime + 61000);

    expect(checkRateLimit(event)).toBe(true);
    jest.useRealTimers();
  });

  it('should allow requests after ban expires', () => {
    jest.useFakeTimers();
    const startTime = Date.now();
    jest.setSystemTime(startTime);

    const ip = '192.168.1.6';
    banIp(ip, 10000); // 10s ban
    expect(isIpBanned(ip)).toBe(true);

    jest.advanceTimersByTime(11000);
    jest.setSystemTime(startTime + 11000);

    expect(isIpBanned(ip)).toBe(false);
    jest.useRealTimers();
  });

  it('should allow manual unbanning', () => {
    const ip = '192.168.1.7';
    banIp(ip);
    expect(isIpBanned(ip)).toBe(true);
    unbanIp(ip);
    expect(isIpBanned(ip)).toBe(false);
  });

  it('should track rate limit per IP independently', () => {
    const event1: SilkerEvent = {
      ...baseEvent,
      ip: '192.168.1.10'
    };
    const event2: SilkerEvent = {
      ...baseEvent,
      ip: '192.168.1.20'
    };

    for (let i = 0; i < 6; i++) {
      checkRateLimit(event1);
    }

    expect(checkRateLimit(event1)).toBe(true);
    expect(checkRateLimit(event2)).toBe(false);
  });

  it('should clean up expired entries', async () => {
    jest.useFakeTimers();
    const startTime = Date.now();
    jest.setSystemTime(startTime);
    
    const event: SilkerEvent = {
      ...baseEvent,
      ip: '192.168.1.3',
      timestamp: startTime
    };

    for (let i = 0; i < 3; i++) {
      checkRateLimit({ ...event, timestamp: startTime + i });
    }

    jest.advanceTimersByTime(61000);
    jest.setSystemTime(startTime + 61000);

    const newEvent: SilkerEvent = {
      ...baseEvent,
      ip: '192.168.1.3',
      timestamp: Date.now()
    };
    checkRateLimit(newEvent);
    expect(checkRateLimit(newEvent)).toBe(false);
    jest.useRealTimers();
  });

  it('should handle rapid requests correctly', () => {
    const event: SilkerEvent = {
      ...baseEvent,
      ip: '192.168.1.4'
    };

    for (let i = 0; i < 5; i++) {
      checkRateLimit(event);
    }

    expect(checkRateLimit(event)).toBe(true);
  });
});

