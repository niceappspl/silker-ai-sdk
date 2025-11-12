"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const zeroTrust_1 = require("../../src/detection/zeroTrust");
describe('performZeroTrustCheck', () => {
    const baseEvent = {
        method: 'GET',
        url: '/api/test',
        timestamp: Date.now()
    };
    describe('Authentication checks', () => {
        it('should require authentication for non-auth endpoints', () => {
            const event = {
                ...baseEvent,
                headers: {}
            };
            const result = (0, zeroTrust_1.performZeroTrustCheck)(event);
            expect(result.verified).toBe(false);
            expect(result.requirements).toContain('Missing authentication credentials');
        });
        it('should allow requests to login endpoints without auth', () => {
            const event = {
                ...baseEvent,
                url: '/api/login',
                headers: {}
            };
            const result = (0, zeroTrust_1.performZeroTrustCheck)(event);
            expect(result.requirements).not.toContain('Missing authentication credentials');
        });
        it('should allow requests to auth endpoints without auth', () => {
            const event = {
                ...baseEvent,
                url: '/auth/token',
                headers: {}
            };
            const result = (0, zeroTrust_1.performZeroTrustCheck)(event);
            expect(result.requirements).not.toContain('Missing authentication credentials');
        });
        it('should verify authorization header', () => {
            const event = {
                ...baseEvent,
                headers: { authorization: 'Bearer token123' }
            };
            const result = (0, zeroTrust_1.performZeroTrustCheck)(event);
            expect(result.requirements).not.toContain('Missing authentication credentials');
        });
        it('should verify x-api-key header', () => {
            const event = {
                ...baseEvent,
                headers: { 'x-api-key': 'key123' }
            };
            const result = (0, zeroTrust_1.performZeroTrustCheck)(event);
            expect(result.requirements).not.toContain('Missing authentication credentials');
        });
        it('should handle case-insensitive auth headers', () => {
            const event = {
                ...baseEvent,
                headers: { Authorization: 'Bearer token123' }
            };
            const result = (0, zeroTrust_1.performZeroTrustCheck)(event);
            expect(result.requirements).not.toContain('Missing authentication credentials');
        });
    });
    describe('Origin verification', () => {
        it('should require origin for non-GET requests', () => {
            const event = {
                ...baseEvent,
                method: 'POST',
                url: '/user/update', // URL bez /api/ żeby origin był wymagany
                userAgent: 'Mozilla/5.0',
                headers: { authorization: 'Bearer token' }
            };
            const result = (0, zeroTrust_1.performZeroTrustCheck)(event);
            expect(result.requirements).toContain('Missing request origin verification');
        });
        it('should allow GET requests without origin', () => {
            const event = {
                ...baseEvent,
                method: 'GET',
                headers: {}
            };
            const result = (0, zeroTrust_1.performZeroTrustCheck)(event);
            expect(result.requirements).not.toContain('Missing request origin verification');
        });
        it('should allow API endpoints without origin', () => {
            const event = {
                ...baseEvent,
                method: 'POST',
                url: '/api/users',
                headers: {}
            };
            const result = (0, zeroTrust_1.performZeroTrustCheck)(event);
            expect(result.requirements).not.toContain('Missing request origin verification');
        });
        it('should verify origin header', () => {
            const event = {
                ...baseEvent,
                method: 'POST',
                headers: { origin: 'https://example.com' }
            };
            const result = (0, zeroTrust_1.performZeroTrustCheck)(event);
            expect(result.requirements).not.toContain('Missing request origin verification');
        });
        it('should verify referer header', () => {
            const event = {
                ...baseEvent,
                method: 'POST',
                headers: { referer: 'https://example.com' }
            };
            const result = (0, zeroTrust_1.performZeroTrustCheck)(event);
            expect(result.requirements).not.toContain('Missing request origin verification');
        });
    });
    describe('User agent verification', () => {
        it('should require user agent', () => {
            const event = {
                ...baseEvent,
                headers: {}
            };
            const result = (0, zeroTrust_1.performZeroTrustCheck)(event);
            expect(result.requirements).toContain('Missing user agent for device verification');
        });
        it('should allow request with user agent', () => {
            const event = {
                ...baseEvent,
                userAgent: 'Mozilla/5.0',
                headers: {}
            };
            const result = (0, zeroTrust_1.performZeroTrustCheck)(event);
            expect(result.requirements).not.toContain('Missing user agent for device verification');
        });
    });
    describe('Destructive operations', () => {
        it('should require confirmation token for DELETE', () => {
            const event = {
                ...baseEvent,
                method: 'DELETE',
                url: '/user/123', // URL bez /api/ żeby confirmation był wymagany
                userAgent: 'Mozilla/5.0',
                headers: { authorization: 'Bearer token', origin: 'https://example.com' }
            };
            const result = (0, zeroTrust_1.performZeroTrustCheck)(event);
            expect(result.requirements).toContain('Destructive operation requires confirmation token');
        });
        it('should allow DELETE with confirmation token', () => {
            const event = {
                ...baseEvent,
                method: 'DELETE',
                url: '/api/user/123',
                headers: { 'x-confirmation-token': 'token123' }
            };
            const result = (0, zeroTrust_1.performZeroTrustCheck)(event);
            expect(result.requirements).not.toContain('Destructive operation requires confirmation token');
        });
        it('should allow DELETE with delete confirmation header', () => {
            const event = {
                ...baseEvent,
                method: 'DELETE',
                url: '/api/user/123',
                headers: { 'x-delete-confirmation': 'true' }
            };
            const result = (0, zeroTrust_1.performZeroTrustCheck)(event);
            expect(result.requirements).not.toContain('Destructive operation requires confirmation token');
        });
        it('should allow DELETE for API endpoints without confirmation', () => {
            const event = {
                ...baseEvent,
                method: 'DELETE',
                url: '/api/users/123',
                headers: {}
            };
            const result = (0, zeroTrust_1.performZeroTrustCheck)(event);
            expect(result.requirements).not.toContain('Destructive operation requires confirmation token');
        });
    });
    describe('Off-hours access', () => {
        beforeEach(() => {
            jest.useFakeTimers();
        });
        afterEach(() => {
            jest.useRealTimers();
        });
        it('should require additional verification outside business hours', () => {
            jest.setSystemTime(new Date('2024-01-01T03:00:00Z'));
            const event = {
                ...baseEvent,
                headers: {}
            };
            const result = (0, zeroTrust_1.performZeroTrustCheck)(event);
            expect(result.requirements).toContain('Access outside normal business hours requires additional verification');
        });
        it('should allow access during business hours', () => {
            jest.setSystemTime(new Date('2024-01-01T12:00:00Z'));
            const event = {
                ...baseEvent,
                headers: {}
            };
            const result = (0, zeroTrust_1.performZeroTrustCheck)(event);
            expect(result.requirements).not.toContain('Access outside normal business hours requires additional verification');
        });
    });
    describe('Fully verified request', () => {
        it('should verify request with all requirements', () => {
            const event = {
                ...baseEvent,
                method: 'POST',
                userAgent: 'Mozilla/5.0',
                headers: {
                    authorization: 'Bearer token123',
                    origin: 'https://example.com'
                }
            };
            const result = (0, zeroTrust_1.performZeroTrustCheck)(event);
            expect(result.verified).toBe(true);
            expect(result.requirements.length).toBe(0);
        });
    });
});
describe('detectZeroTrustViolation', () => {
    const baseEvent = {
        method: 'GET',
        url: '/api/test',
        timestamp: Date.now()
    };
    it('should detect missing authentication violation', () => {
        const event = {
            ...baseEvent,
            headers: {}
        };
        expect((0, zeroTrust_1.detectZeroTrustViolation)(event)).toBe(true);
    });
    it('should detect destructive operation without confirmation', () => {
        const event = {
            ...baseEvent,
            method: 'DELETE',
            url: '/api/user/123',
            headers: {}
        };
        expect((0, zeroTrust_1.detectZeroTrustViolation)(event)).toBe(true);
    });
    it('should not detect non-critical violations', () => {
        const event = {
            ...baseEvent,
            headers: { authorization: 'Bearer token' }
        };
        expect((0, zeroTrust_1.detectZeroTrustViolation)(event)).toBe(false);
    });
    it('should return false for verified request', () => {
        const event = {
            ...baseEvent,
            method: 'POST',
            userAgent: 'Mozilla/5.0',
            headers: {
                authorization: 'Bearer token123',
                origin: 'https://example.com'
            }
        };
        expect((0, zeroTrust_1.detectZeroTrustViolation)(event)).toBe(false);
    });
});
