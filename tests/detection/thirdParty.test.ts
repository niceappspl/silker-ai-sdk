import { detectThirdPartyRisks, detectThirdPartyAttack } from '../../src/detection/thirdParty';
import { SilkerEvent } from '../../src/types';

const outgoing = (event: Partial<SilkerEvent>): SilkerEvent => ({
  method: 'GET',
  url: '/api/test',
  timestamp: Date.now(),
  direction: 'outgoing',
  ...event,
});

describe('detectThirdPartyRisks (outbound egress only)', () => {
  describe('Risky domains', () => {
    it('should detect pastebin.com on outbound fetch', () => {
      const event = outgoing({ url: 'https://pastebin.com/raw/abc123' });
      const result = detectThirdPartyRisks(event);
      expect(result.risky).toBe(true);
      expect(result.issues).toContain('Known exfiltration host blocked: pastebin.com');
    });

    it('should detect ngrok.io on outbound fetch', () => {
      const event = outgoing({ url: 'https://abc123.ngrok.io/api' });
      expect(detectThirdPartyRisks(event).risky).toBe(true);
    });

    it('should not flag incoming relative URLs', () => {
      const event: SilkerEvent = {
        method: 'POST',
        url: '/api/login',
        direction: 'incoming',
        payload: JSON.stringify({ username: 'admin', password: 'test123' }),
        timestamp: Date.now(),
      };
      expect(detectThirdPartyRisks(event).risky).toBe(false);
      expect(detectThirdPartyAttack(event)).toBe(false);
    });

    it('should not flag incoming webhook route paths', () => {
      const event: SilkerEvent = {
        method: 'POST',
        url: '/api/webhook/stripe',
        direction: 'incoming',
        timestamp: Date.now(),
      };
      expect(detectThirdPartyRisks(event).risky).toBe(false);
    });
  });

  describe('Webhook allowlist (outbound only)', () => {
    it('should allow Slack webhooks', () => {
      const event = outgoing({ url: 'https://hooks.slack.com/services/abc/123' });
      expect(detectThirdPartyRisks(event).risky).toBe(false);
    });

    it('should flag outbound webhook to unknown host', () => {
      const event = outgoing({ url: 'https://evil.com/webhook/collect' });
      const result = detectThirdPartyRisks(event);
      expect(result.risky).toBe(true);
      expect(result.issues.some(i => i.includes('non-allowlisted host'))).toBe(true);
    });

    it('should not flag normal outbound API calls without webhook path', () => {
      const event = outgoing({
        method: 'POST',
        url: 'https://api.stripe.com/v1/charges',
        payload: JSON.stringify({ amount: 100 }),
      });
      expect(detectThirdPartyRisks(event).risky).toBe(false);
    });
  });

  describe('No payload guessing', () => {
    it('should not block outbound POST with password in body to allowed API', () => {
      const event = outgoing({
        method: 'POST',
        url: 'https://api.example.com/v1/users',
        payload: JSON.stringify({ password: 'secret123', email: 'user@example.com' }),
      });
      expect(detectThirdPartyRisks(event).risky).toBe(false);
    });
  });
});

describe('detectThirdPartyAttack', () => {
  it('should detect exfil host on outbound', () => {
    expect(
      detectThirdPartyAttack(outgoing({ url: 'https://pastebin.com/raw/abc123' }))
    ).toBe(true);
  });

  it('should not detect localhost outbound as attack', () => {
    expect(
      detectThirdPartyAttack(outgoing({ url: 'http://localhost:3000/api' }))
    ).toBe(false);
  });

  it('should ignore events without direction outgoing', () => {
    const event: SilkerEvent = {
      method: 'GET',
      url: 'https://pastebin.com/raw/abc123',
      timestamp: Date.now(),
    };
    expect(detectThirdPartyAttack(event)).toBe(false);
  });
});
