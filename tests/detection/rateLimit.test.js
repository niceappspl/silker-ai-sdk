"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const rateLimit_1 = require("../../src/detection/rateLimit");
describe('checkRateLimit', () => {
    const baseEvent = {
        method: 'GET',
        url: '/api/test',
        timestamp: Date.now()
    };
    it('should return false when IP is missing', () => {
        const event = {
            ...baseEvent,
            ip: undefined
        };
        expect((0, rateLimit_1.checkRateLimit)(event)).toBe(false);
    });
    it('should allow requests within rate limit', () => {
        const event = {
            ...baseEvent,
            ip: '192.168.1.1'
        };
        for (let i = 0; i < 5; i++) {
            expect((0, rateLimit_1.checkRateLimit)(event)).toBe(false);
        }
    });
    it('should block requests exceeding rate limit', () => {
        const event = {
            ...baseEvent,
            ip: '192.168.1.1'
        };
        for (let i = 0; i < 5; i++) {
            (0, rateLimit_1.checkRateLimit)(event);
        }
        expect((0, rateLimit_1.checkRateLimit)(event)).toBe(true);
    });
    it('should reset rate limit after time window', async () => {
        jest.useFakeTimers();
        const startTime = Date.now();
        jest.setSystemTime(startTime);
        const event = {
            ...baseEvent,
            ip: '192.168.1.2',
            timestamp: startTime
        };
        for (let i = 0; i < 6; i++) {
            (0, rateLimit_1.checkRateLimit)({ ...event, timestamp: startTime + i });
        }
        expect((0, rateLimit_1.checkRateLimit)({ ...event, timestamp: startTime + 6 })).toBe(true);
        jest.advanceTimersByTime(61000);
        jest.setSystemTime(startTime + 61000);
        const newEvent = {
            ...baseEvent,
            ip: '192.168.1.2',
            timestamp: Date.now()
        };
        expect((0, rateLimit_1.checkRateLimit)(newEvent)).toBe(false);
        jest.useRealTimers();
    });
    it('should track rate limit per IP independently', () => {
        const event1 = {
            ...baseEvent,
            ip: '192.168.1.10'
        };
        const event2 = {
            ...baseEvent,
            ip: '192.168.1.20'
        };
        for (let i = 0; i < 6; i++) {
            (0, rateLimit_1.checkRateLimit)(event1);
        }
        expect((0, rateLimit_1.checkRateLimit)(event1)).toBe(true);
        expect((0, rateLimit_1.checkRateLimit)(event2)).toBe(false);
    });
    it('should clean up expired entries', async () => {
        jest.useFakeTimers();
        const startTime = Date.now();
        jest.setSystemTime(startTime);
        const event = {
            ...baseEvent,
            ip: '192.168.1.3',
            timestamp: startTime
        };
        for (let i = 0; i < 3; i++) {
            (0, rateLimit_1.checkRateLimit)({ ...event, timestamp: startTime + i });
        }
        jest.advanceTimersByTime(61000);
        jest.setSystemTime(startTime + 61000);
        const newEvent = {
            ...baseEvent,
            ip: '192.168.1.3',
            timestamp: Date.now()
        };
        (0, rateLimit_1.checkRateLimit)(newEvent);
        expect((0, rateLimit_1.checkRateLimit)(newEvent)).toBe(false);
        jest.useRealTimers();
    });
    it('should handle rapid requests correctly', () => {
        const event = {
            ...baseEvent,
            ip: '192.168.1.4'
        };
        for (let i = 0; i < 5; i++) {
            (0, rateLimit_1.checkRateLimit)(event);
        }
        expect((0, rateLimit_1.checkRateLimit)(event)).toBe(true);
    });
});
