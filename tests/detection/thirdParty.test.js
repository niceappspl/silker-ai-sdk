"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const thirdParty_1 = require("../../src/detection/thirdParty");
describe('detectThirdPartyRisks', () => {
    const baseEvent = {
        method: 'GET',
        url: '/api/test',
        timestamp: Date.now()
    };
    describe('Risky domains', () => {
        it('should detect pastebin.com', () => {
            const event = {
                ...baseEvent,
                url: 'https://pastebin.com/raw/abc123'
            };
            const result = (0, thirdParty_1.detectThirdPartyRisks)(event);
            expect(result.risky).toBe(true);
            expect(result.issues).toContain('Risky third-party service detected: pastebin.com');
        });
        it('should detect transfer.sh', () => {
            const event = {
                ...baseEvent,
                url: 'https://transfer.sh/file.txt'
            };
            const result = (0, thirdParty_1.detectThirdPartyRisks)(event);
            expect(result.risky).toBe(true);
        });
        it('should detect ngrok.io', () => {
            const event = {
                ...baseEvent,
                url: 'https://abc123.ngrok.io/api'
            };
            const result = (0, thirdParty_1.detectThirdPartyRisks)(event);
            expect(result.risky).toBe(true);
        });
        it('should detect webhook.site', () => {
            const event = {
                ...baseEvent,
                url: 'https://webhook.site/abc123'
            };
            const result = (0, thirdParty_1.detectThirdPartyRisks)(event);
            expect(result.risky).toBe(true);
        });
        it('should not detect legitimate domain', () => {
            const event = {
                ...baseEvent,
                url: 'https://api.github.com/webhook'
            };
            const result = (0, thirdParty_1.detectThirdPartyRisks)(event);
            expect(result.risky).toBe(false);
        });
    });
    describe('Webhook validation', () => {
        it('should allow allowed webhook domains', () => {
            const event = {
                ...baseEvent,
                url: 'https://hooks.slack.com/services/abc/123'
            };
            const result = (0, thirdParty_1.detectThirdPartyRisks)(event);
            expect(result.risky).toBe(false);
        });
        it('should allow discord webhooks', () => {
            const event = {
                ...baseEvent,
                url: 'https://discord.com/api/webhooks/123'
            };
            const result = (0, thirdParty_1.detectThirdPartyRisks)(event);
            expect(result.risky).toBe(false);
        });
        it('should detect unexpected webhook destination', () => {
            const event = {
                ...baseEvent,
                url: 'https://evil.com/webhook'
            };
            const result = (0, thirdParty_1.detectThirdPartyRisks)(event);
            expect(result.risky).toBe(true);
            expect(result.issues.some(i => i.includes('Unexpected webhook destination'))).toBe(true);
        });
        it('should handle invalid webhook URL', () => {
            const event = {
                ...baseEvent,
                url: 'not-a-valid-webhook-url'
            };
            const result = (0, thirdParty_1.detectThirdPartyRisks)(event);
            expect(result.issues.some(i => i.includes('Invalid webhook URL format'))).toBe(true);
        });
    });
    describe('API key exposure', () => {
        it('should detect API key in payload for third-party request', () => {
            const event = {
                ...baseEvent,
                url: 'https://api.example.com/webhook',
                payload: 'api_key=sk-1234567890abcdef123456'
            };
            const result = (0, thirdParty_1.detectThirdPartyRisks)(event);
            expect(result.risky).toBe(true);
            expect(result.issues).toContain('Potential API key exposure in third-party request');
        });
        it('should detect bearer token in payload', () => {
            const event = {
                ...baseEvent,
                url: 'https://api.example.com/webhook',
                payload: 'authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
            };
            const result = (0, thirdParty_1.detectThirdPartyRisks)(event);
            expect(result.risky).toBe(true);
        });
        it('should not detect API key for non-api/webhook URLs', () => {
            const event = {
                ...baseEvent,
                url: '/api/local',
                payload: 'api_key=sk-1234567890abcdef123456'
            };
            const result = (0, thirdParty_1.detectThirdPartyRisks)(event);
            expect(result.issues).not.toContain('Potential API key exposure in third-party request');
        });
    });
    describe('Data exfiltration', () => {
        it('should detect large payload in third-party request', () => {
            const largePayload = 'x'.repeat(10001);
            const event = {
                ...baseEvent,
                method: 'POST',
                url: 'https://api.example.com/webhook',
                payload: largePayload
            };
            const result = (0, thirdParty_1.detectThirdPartyRisks)(event);
            expect(result.risky).toBe(true);
            expect(result.issues).toContain('Large payload in third-party request - potential data exfiltration');
        });
        it('should detect sensitive data in third-party request', () => {
            const event = {
                ...baseEvent,
                method: 'POST',
                url: 'https://api.example.com/webhook',
                payload: JSON.stringify({ password: 'secret123', email: 'user@example.com' })
            };
            const result = (0, thirdParty_1.detectThirdPartyRisks)(event);
            expect(result.risky).toBe(true);
            expect(result.issues).toContain('Sensitive data detected in third-party request');
        });
        it('should detect credit card in third-party request', () => {
            const event = {
                ...baseEvent,
                method: 'POST',
                url: 'https://api.example.com/webhook',
                payload: JSON.stringify({ card: '4111-1111-1111-1111' })
            };
            const result = (0, thirdParty_1.detectThirdPartyRisks)(event);
            expect(result.risky).toBe(true);
        });
        it('should not check exfiltration for GET requests', () => {
            const largePayload = 'x'.repeat(10001);
            const event = {
                ...baseEvent,
                method: 'GET',
                url: 'https://api.example.com/webhook',
                payload: largePayload
            };
            const result = (0, thirdParty_1.detectThirdPartyRisks)(event);
            expect(result.issues).not.toContain('Large payload in third-party request');
        });
    });
    describe('No risks', () => {
        it('should return no risks for legitimate request', () => {
            const event = {
                ...baseEvent,
                url: 'https://api.github.com/webhook',
                payload: JSON.stringify({ action: 'opened' })
            };
            const result = (0, thirdParty_1.detectThirdPartyRisks)(event);
            expect(result.risky).toBe(false);
        });
        it('should return no risks when URL is missing', () => {
            const event = {
                ...baseEvent,
                url: ''
            };
            const result = (0, thirdParty_1.detectThirdPartyRisks)(event);
            expect(result.risky).toBe(false);
        });
    });
});
describe('detectThirdPartyAttack', () => {
    const baseEvent = {
        method: 'GET',
        url: '/api/test',
        timestamp: Date.now()
    };
    it('should detect third-party attack', () => {
        const event = {
            ...baseEvent,
            url: 'https://pastebin.com/raw/abc123'
        };
        expect((0, thirdParty_1.detectThirdPartyAttack)(event)).toBe(true);
    });
    it('should not detect localhost as attack', () => {
        const event = {
            ...baseEvent,
            url: 'http://localhost:3000/api'
        };
        expect((0, thirdParty_1.detectThirdPartyAttack)(event)).toBe(false);
    });
    it('should not detect 127.0.0.1 as attack', () => {
        const event = {
            ...baseEvent,
            url: 'http://127.0.0.1:3000/api'
        };
        expect((0, thirdParty_1.detectThirdPartyAttack)(event)).toBe(false);
    });
    it('should return false for legitimate request', () => {
        const event = {
            ...baseEvent,
            url: 'https://api.github.com/webhook'
        };
        expect((0, thirdParty_1.detectThirdPartyAttack)(event)).toBe(false);
    });
    it('should return false when URL is missing', () => {
        const event = {
            ...baseEvent,
            url: ''
        };
        expect((0, thirdParty_1.detectThirdPartyAttack)(event)).toBe(false);
    });
});
