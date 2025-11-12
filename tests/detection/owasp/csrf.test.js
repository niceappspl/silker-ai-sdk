"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const csrf_1 = require("../../../src/detection/owasp/csrf");
describe('detectCsrfAttack', () => {
    const baseEvent = {
        method: 'GET',
        url: '/api/test',
        timestamp: Date.now()
    };
    describe('POST requests', () => {
        it('should detect missing CSRF token in header', () => {
            const event = {
                ...baseEvent,
                method: 'POST',
                url: '/user/update', // URL bez /api/ żeby CSRF był wymagany
                headers: {}
            };
            expect((0, csrf_1.detectCsrfAttack)(event, {})).toBe(true);
        });
        it('should allow POST with CSRF token in header', () => {
            const event = {
                ...baseEvent,
                method: 'POST',
                url: '/user/update',
                headers: {}
            };
            const headers = { 'x-csrf-token': 'token123' };
            expect((0, csrf_1.detectCsrfAttack)(event, headers)).toBe(false);
        });
        it('should allow POST with CSRF token in alternate header', () => {
            const event = {
                ...baseEvent,
                method: 'POST',
                headers: {}
            };
            const headers = { 'csrf-token': 'token123' };
            expect((0, csrf_1.detectCsrfAttack)(event, headers)).toBe(false);
        });
        it('should allow POST with CSRF token in payload', () => {
            const event = {
                ...baseEvent,
                method: 'POST',
                payload: JSON.stringify({ csrf: 'token123', name: 'John' }),
                headers: {}
            };
            expect((0, csrf_1.detectCsrfAttack)(event, {})).toBe(false);
        });
        it('should allow POST with _token in payload', () => {
            const event = {
                ...baseEvent,
                method: 'POST',
                payload: JSON.stringify({ _token: 'token123' }),
                headers: {}
            };
            expect((0, csrf_1.detectCsrfAttack)(event, {})).toBe(false);
        });
        it('should allow POST with authenticity_token in payload', () => {
            const event = {
                ...baseEvent,
                method: 'POST',
                payload: JSON.stringify({ authenticity_token: 'token123' }),
                headers: {}
            };
            expect((0, csrf_1.detectCsrfAttack)(event, {})).toBe(false);
        });
    });
    describe('PUT requests', () => {
        it('should detect missing CSRF token', () => {
            const event = {
                ...baseEvent,
                method: 'PUT',
                url: '/user/123',
                headers: {}
            };
            expect((0, csrf_1.detectCsrfAttack)(event, {})).toBe(true);
        });
        it('should allow PUT with CSRF token', () => {
            const event = {
                ...baseEvent,
                method: 'PUT',
                url: '/user/123',
                headers: {}
            };
            const headers = { 'x-csrf-token': 'token123' };
            expect((0, csrf_1.detectCsrfAttack)(event, headers)).toBe(false);
        });
    });
    describe('PATCH requests', () => {
        it('should detect missing CSRF token', () => {
            const event = {
                ...baseEvent,
                method: 'PATCH',
                url: '/user/123',
                headers: {}
            };
            expect((0, csrf_1.detectCsrfAttack)(event, {})).toBe(true);
        });
        it('should allow PATCH with CSRF token', () => {
            const event = {
                ...baseEvent,
                method: 'PATCH',
                url: '/user/123',
                headers: {}
            };
            const headers = { 'x-csrf-token': 'token123' };
            expect((0, csrf_1.detectCsrfAttack)(event, headers)).toBe(false);
        });
    });
    describe('DELETE requests', () => {
        it('should detect missing CSRF token', () => {
            const event = {
                ...baseEvent,
                method: 'DELETE',
                url: '/user/123',
                headers: {}
            };
            expect((0, csrf_1.detectCsrfAttack)(event, {})).toBe(true);
        });
        it('should allow DELETE with CSRF token', () => {
            const event = {
                ...baseEvent,
                method: 'DELETE',
                url: '/user/123',
                headers: {}
            };
            const headers = { 'x-csrf-token': 'token123' };
            expect((0, csrf_1.detectCsrfAttack)(event, headers)).toBe(false);
        });
    });
    describe('API endpoints', () => {
        it('should allow POST to API endpoints without CSRF token', () => {
            const event = {
                ...baseEvent,
                method: 'POST',
                url: '/api/users',
                headers: {}
            };
            expect((0, csrf_1.detectCsrfAttack)(event, {})).toBe(false);
        });
        it('should allow PUT to API endpoints without CSRF token', () => {
            const event = {
                ...baseEvent,
                method: 'PUT',
                url: '/api/users/123',
                headers: {}
            };
            expect((0, csrf_1.detectCsrfAttack)(event, {})).toBe(false);
        });
    });
    describe('GET requests', () => {
        it('should not check CSRF for GET requests', () => {
            const event = {
                ...baseEvent,
                method: 'GET',
                headers: {}
            };
            expect((0, csrf_1.detectCsrfAttack)(event, {})).toBe(false);
        });
    });
});
