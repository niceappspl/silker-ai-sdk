import { checkRateLimit } from '../../src/detection/rateLimit';
import { SilkerEvent } from '../../src/types';

describe('checkRateLimit', () => {
  const baseEvent: SilkerEvent = {
    method: 'GET',
    url: '/api/test',
    timestamp: Date.now()
  };

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

  it('should block requests exceeding rate limit', () => {
    const event: SilkerEvent = {
      ...baseEvent,
      ip: '192.168.1.1'
    };

    for (let i = 0; i < 5; i++) {
      checkRateLimit(event);
    }

    expect(checkRateLimit(event)).toBe(true);
  });

  it('should reset rate limit after time window', async () => {
    jest.useFakeTimers();
    const startTime = Date.now();
    jest.setSystemTime(startTime);
    
    const event: SilkerEvent = {
      ...baseEvent,
      ip: '192.168.1.2',
      timestamp: startTime
    };

    for (let i = 0; i < 6; i++) {
      checkRateLimit({ ...event, timestamp: startTime + i });
    }

    expect(checkRateLimit({ ...event, timestamp: startTime + 6 })).toBe(true);

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

