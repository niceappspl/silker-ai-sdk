import { validateSecurityHeaders } from '../../src/validation/securityHeaders';

describe('validateSecurityHeaders', () => {
  it('should return valid when all required headers present', () => {
    const headers = {
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'x-xss-protection': '1; mode=block',
      'strict-transport-security': 'max-age=31536000'
    };
    const result = validateSecurityHeaders(headers);
    expect(result.valid).toBe(true);
    expect(result.missing).toEqual([]);
  });

  it('should detect missing headers', () => {
    const headers = {
      'x-content-type-options': 'nosniff'
    };
    const result = validateSecurityHeaders(headers);
    expect(result.valid).toBe(false);
    expect(result.missing.length).toBeGreaterThan(0);
    expect(result.missing).toContain('x-frame-options');
  });

  it('should handle case-insensitive header names', () => {
    const headers = {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Strict-Transport-Security': 'max-age=31536000'
    };
    const result = validateSecurityHeaders(headers);
    expect(result.valid).toBe(true);
  });

  it('should return all missing headers when none present', () => {
    const headers = {};
    const result = validateSecurityHeaders(headers);
    expect(result.valid).toBe(false);
    expect(result.missing.length).toBe(4);
    expect(result.missing).toContain('x-content-type-options');
    expect(result.missing).toContain('x-frame-options');
    expect(result.missing).toContain('x-xss-protection');
    expect(result.missing).toContain('strict-transport-security');
  });

  it('should handle undefined headers', () => {
    const result = validateSecurityHeaders(undefined);
    expect(result.valid).toBe(false);
    expect(result.missing.length).toBe(4);
  });

  it('should handle null headers', () => {
    const result = validateSecurityHeaders(null);
    expect(result.valid).toBe(false);
    expect(result.missing.length).toBe(4);
  });

  it('should detect partial missing headers', () => {
    const headers = {
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY'
    };
    const result = validateSecurityHeaders(headers);
    expect(result.valid).toBe(false);
    expect(result.missing).toContain('x-xss-protection');
    expect(result.missing).toContain('strict-transport-security');
    expect(result.missing).not.toContain('x-content-type-options');
    expect(result.missing).not.toContain('x-frame-options');
  });
});

