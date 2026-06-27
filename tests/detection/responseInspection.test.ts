import { inspectResponseText, isScannableContentType } from '../../src/detection/responseInspection';

describe('inspectResponseText', () => {
  it('detects a leaked API key in a response body', () => {
    const body = JSON.stringify({ ok: true, api_key: 'abcdefghijklmnopqrstuvwx1234' });
    const result = inspectResponseText(body);
    expect(result.leaked).toBe(true);
    expect(result.findings.some(f => f.includes('API Key'))).toBe(true);
  });

  it('detects PII (email) in an outbound response', () => {
    const body = 'Here is the user record: john.doe@example.com, all good.';
    const result = inspectResponseText(body);
    expect(result.leaked).toBe(true);
    expect(result.findings.some(f => f.includes('email'))).toBe(true);
  });

  it('does not flag a clean response', () => {
    const result = inspectResponseText(JSON.stringify({ status: 'ok', items: [1, 2, 3] }));
    expect(result.leaked).toBe(false);
  });

  it('returns empty for empty body', () => {
    expect(inspectResponseText('').leaked).toBe(false);
  });
});

describe('isScannableContentType', () => {
  it('scans json/text content types', () => {
    expect(isScannableContentType('application/json')).toBe(true);
    expect(isScannableContentType('text/html; charset=utf-8')).toBe(true);
    expect(isScannableContentType('text/event-stream')).toBe(true);
  });

  it('skips binary content types', () => {
    expect(isScannableContentType('image/png')).toBe(false);
    expect(isScannableContentType('application/octet-stream')).toBe(false);
    expect(isScannableContentType('video/mp4')).toBe(false);
  });

  it('scans when content type is missing (conservative)', () => {
    expect(isScannableContentType(null)).toBe(true);
  });
});
