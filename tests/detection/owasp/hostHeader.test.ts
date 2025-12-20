import { detectHostHeaderInjection } from '../../../src/detection/owasp/hostHeader';
import { SilkerEvent } from '../../../src/types';

describe('detectHostHeaderInjection', () => {
  const baseEvent: SilkerEvent = {
    method: 'GET',
    url: '/api/test',
    timestamp: Date.now()
  };

  it('should detect newline character in host header', () => {
    const headers = { host: 'example.com\ninjected' };
    expect(detectHostHeaderInjection(baseEvent, headers)).toBe(true);
  });

  it('should detect carriage return in host header', () => {
    const headers = { host: 'example.com\rinjected' };
    expect(detectHostHeaderInjection(baseEvent, headers)).toBe(true);
  });

  it('should allow valid host when no allowed hosts configured', () => {
    const headers = { host: 'example.com' };
    expect(detectHostHeaderInjection(baseEvent, headers)).toBe(false);
  });

  it('should allow host from allowed list', () => {
    const allowedHosts = ['example.com', 'api.example.com'];
    const headers = { host: 'example.com' };
    expect(detectHostHeaderInjection(baseEvent, headers, allowedHosts)).toBe(false);
  });

  it('should allow host that includes allowed host', () => {
    const allowedHosts = ['example.com', 'api.example.com'];
    const headers = { host: 'api.example.com' };
    expect(detectHostHeaderInjection(baseEvent, headers, allowedHosts)).toBe(false);
  });

  it('should detect host not in allowed list', () => {
    const allowedHosts = ['example.com'];
    const headers = { host: 'evil.com' };
    expect(detectHostHeaderInjection(baseEvent, headers, allowedHosts)).toBe(true);
  });

  it('should handle case-insensitive host header key', () => {
    const headers1 = { Host: 'example.com\ninjected' };
    expect(detectHostHeaderInjection(baseEvent, headers1)).toBe(true);
    
    const headers2 = { HOST: 'example.com\ninjected' };
    expect(detectHostHeaderInjection(baseEvent, headers2)).toBe(true);
  });

  it('should return false when no host header present', () => {
    expect(detectHostHeaderInjection(baseEvent, {})).toBe(false);
  });

  it('should return false when headers undefined', () => {
    expect(detectHostHeaderInjection(baseEvent)).toBe(false);
  });

  it('should handle multiple allowed hosts', () => {
    const allowedHosts = ['example.com', 'test.com', 'api.example.com'];
    const headers = { host: 'test.com' };
    expect(detectHostHeaderInjection(baseEvent, headers, allowedHosts)).toBe(false);
  });
});

