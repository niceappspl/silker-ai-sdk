"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const idor_1 = require("../../../src/detection/owasp/idor");
describe('detectIdorAttack', () => {
    const baseEvent = {
        method: 'GET',
        url: '/api/test',
        timestamp: Date.now()
    };
    describe('User endpoint patterns', () => {
        it('should detect suspiciously large user ID', () => {
            const event = {
                ...baseEvent,
                url: '/api/user/9999999'
            };
            expect((0, idor_1.detectIdorAttack)(event)).toBe(true);
        });
        it('should detect negative user ID', () => {
            const event = {
                ...baseEvent,
                url: '/api/user/-1'
            };
            expect((0, idor_1.detectIdorAttack)(event)).toBe(true);
        });
        it('should allow normal user ID', () => {
            const event = {
                ...baseEvent,
                url: '/api/user/123'
            };
            expect((0, idor_1.detectIdorAttack)(event)).toBe(false);
        });
        it('should allow small user ID', () => {
            const event = {
                ...baseEvent,
                url: '/api/user/1'
            };
            expect((0, idor_1.detectIdorAttack)(event)).toBe(false);
        });
    });
    describe('Account endpoint patterns', () => {
        it('should detect suspicious account ID', () => {
            const event = {
                ...baseEvent,
                url: '/api/account/1000000'
            };
            expect((0, idor_1.detectIdorAttack)(event)).toBe(true);
        });
        it('should allow normal account ID', () => {
            const event = {
                ...baseEvent,
                url: '/api/account/456'
            };
            expect((0, idor_1.detectIdorAttack)(event)).toBe(false);
        });
    });
    describe('Profile endpoint patterns', () => {
        it('should detect suspicious profile ID', () => {
            const event = {
                ...baseEvent,
                url: '/api/profile/2000000'
            };
            expect((0, idor_1.detectIdorAttack)(event)).toBe(true);
        });
        it('should allow normal profile ID', () => {
            const event = {
                ...baseEvent,
                url: '/api/profile/789'
            };
            expect((0, idor_1.detectIdorAttack)(event)).toBe(false);
        });
    });
    describe('Data endpoint patterns', () => {
        it('should detect suspicious data ID', () => {
            const event = {
                ...baseEvent,
                url: '/api/data/3000000'
            };
            expect((0, idor_1.detectIdorAttack)(event)).toBe(true);
        });
        it('should allow normal data ID', () => {
            const event = {
                ...baseEvent,
                url: '/api/data/321'
            };
            expect((0, idor_1.detectIdorAttack)(event)).toBe(false);
        });
    });
    describe('Record endpoint patterns', () => {
        it('should detect suspicious record ID', () => {
            const event = {
                ...baseEvent,
                url: '/api/record/4000000'
            };
            expect((0, idor_1.detectIdorAttack)(event)).toBe(true);
        });
        it('should allow normal record ID', () => {
            const event = {
                ...baseEvent,
                url: '/api/record/654'
            };
            expect((0, idor_1.detectIdorAttack)(event)).toBe(false);
        });
    });
    describe('ID mismatch in payload', () => {
        it('should detect ID mismatch between URL and payload', () => {
            const event = {
                ...baseEvent,
                url: '/api/user/123',
                payload: JSON.stringify({ id: 456 })
            };
            expect((0, idor_1.detectIdorAttack)(event, JSON.parse(event.payload))).toBe(true);
        });
        it('should detect userId mismatch', () => {
            const event = {
                ...baseEvent,
                url: '/api/user/123',
                payload: JSON.stringify({ userId: 456 })
            };
            expect((0, idor_1.detectIdorAttack)(event, JSON.parse(event.payload))).toBe(true);
        });
        it('should detect accountId mismatch', () => {
            const event = {
                ...baseEvent,
                url: '/api/account/123',
                payload: JSON.stringify({ accountId: 456 })
            };
            expect((0, idor_1.detectIdorAttack)(event, JSON.parse(event.payload))).toBe(true);
        });
        it('should allow matching IDs', () => {
            const event = {
                ...baseEvent,
                url: '/api/user/123',
                payload: JSON.stringify({ id: 123 })
            };
            expect((0, idor_1.detectIdorAttack)(event, JSON.parse(event.payload))).toBe(false);
        });
        it('should allow matching userId', () => {
            const event = {
                ...baseEvent,
                url: '/api/user/123',
                payload: JSON.stringify({ userId: 123 })
            };
            expect((0, idor_1.detectIdorAttack)(event, JSON.parse(event.payload))).toBe(false);
        });
    });
    describe('Edge cases', () => {
        it('should return false when URL is missing', () => {
            const event = {
                ...baseEvent,
                url: ''
            };
            expect((0, idor_1.detectIdorAttack)(event)).toBe(false);
        });
        it('should handle URL without ID pattern', () => {
            const event = {
                ...baseEvent,
                url: '/api/users'
            };
            expect((0, idor_1.detectIdorAttack)(event)).toBe(false);
        });
        it('should handle case-insensitive URL patterns', () => {
            const event = {
                ...baseEvent,
                url: '/api/USER/1000000'
            };
            expect((0, idor_1.detectIdorAttack)(event)).toBe(true);
        });
        it('should handle payload without ID fields', () => {
            const event = {
                ...baseEvent,
                url: '/api/user/123',
                payload: JSON.stringify({ name: 'John' })
            };
            expect((0, idor_1.detectIdorAttack)(event, JSON.parse(event.payload))).toBe(false);
        });
    });
});
