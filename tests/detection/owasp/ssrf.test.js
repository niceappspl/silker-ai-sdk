"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const ssrf_1 = require("../../../src/detection/owasp/ssrf");
describe('detectSsrfAttack', () => {
    const baseEvent = {
        method: 'GET',
        url: '/api/test',
        timestamp: Date.now()
    };
    describe('Localhost detection', () => {
        it('should detect localhost in URL', () => {
            const event = {
                ...baseEvent,
                url: 'http://localhost:8080/api'
            };
            expect((0, ssrf_1.detectSsrfAttack)(event)).toBe(true);
        });
        it('should detect localhost case-insensitive', () => {
            const event = {
                ...baseEvent,
                url: 'http://LOCALHOST:8080/api'
            };
            expect((0, ssrf_1.detectSsrfAttack)(event)).toBe(true);
        });
    });
    describe('Private IP addresses', () => {
        it('should detect 127.0.0.1', () => {
            const event = {
                ...baseEvent,
                url: 'http://127.0.0.1:8080/api'
            };
            expect((0, ssrf_1.detectSsrfAttack)(event)).toBe(true);
        });
        it('should detect 0.0.0.0', () => {
            const event = {
                ...baseEvent,
                url: 'http://0.0.0.0:8080/api'
            };
            expect((0, ssrf_1.detectSsrfAttack)(event)).toBe(true);
        });
        it('should detect 10.x.x.x range', () => {
            const event = {
                ...baseEvent,
                url: 'http://10.0.0.1:8080/api'
            };
            expect((0, ssrf_1.detectSsrfAttack)(event)).toBe(true);
        });
        it('should detect 172.16-31.x.x range', () => {
            const event = {
                ...baseEvent,
                url: 'http://172.16.0.1:8080/api'
            };
            expect((0, ssrf_1.detectSsrfAttack)(event)).toBe(true);
        });
        it('should detect 192.168.x.x range', () => {
            const event = {
                ...baseEvent,
                url: 'http://192.168.1.1:8080/api'
            };
            expect((0, ssrf_1.detectSsrfAttack)(event)).toBe(true);
        });
        it('should detect 169.254.x.x range', () => {
            const event = {
                ...baseEvent,
                url: 'http://169.254.1.1:8080/api'
            };
            expect((0, ssrf_1.detectSsrfAttack)(event)).toBe(true);
        });
    });
    describe('IPv6 addresses', () => {
        it('should detect ::1 (IPv6 localhost)', () => {
            const event = {
                ...baseEvent,
                url: 'http://[::1]:8080/api'
            };
            expect((0, ssrf_1.detectSsrfAttack)(event)).toBe(true);
        });
        it('should detect [::1] format', () => {
            const event = {
                ...baseEvent,
                url: 'http://[::1]/api'
            };
            expect((0, ssrf_1.detectSsrfAttack)(event)).toBe(true);
        });
        it('should detect fd00: (IPv6 private)', () => {
            const event = {
                ...baseEvent,
                url: 'http://[fd00::1]/api'
            };
            expect((0, ssrf_1.detectSsrfAttack)(event)).toBe(true);
        });
    });
    describe('Cloud metadata endpoints', () => {
        it('should detect metadata.google', () => {
            const event = {
                ...baseEvent,
                url: 'http://metadata.google.internal/computeMetadata/v1/'
            };
            expect((0, ssrf_1.detectSsrfAttack)(event)).toBe(true);
        });
        it('should detect 169.254.169.254 (AWS metadata)', () => {
            const event = {
                ...baseEvent,
                url: 'http://169.254.169.254/latest/meta-data/'
            };
            expect((0, ssrf_1.detectSsrfAttack)(event)).toBe(true);
        });
        it('should detect internal keyword', () => {
            const event = {
                ...baseEvent,
                url: 'http://internal.api.example.com'
            };
            expect((0, ssrf_1.detectSsrfAttack)(event)).toBe(true);
        });
    });
    describe('Legitimate URLs', () => {
        it('should allow public URLs', () => {
            const event = {
                ...baseEvent,
                url: 'https://api.example.com/users'
            };
            expect((0, ssrf_1.detectSsrfAttack)(event)).toBe(false);
        });
        it('should allow relative URLs', () => {
            const event = {
                ...baseEvent,
                url: '/api/users'
            };
            expect((0, ssrf_1.detectSsrfAttack)(event)).toBe(false);
        });
        it('should return false when URL is missing', () => {
            const event = {
                ...baseEvent,
                url: ''
            };
            expect((0, ssrf_1.detectSsrfAttack)(event)).toBe(false);
        });
    });
});
