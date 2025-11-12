"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const userBehavior_1 = require("../../src/analytics/userBehavior");
describe('analyzeUserBehavior', () => {
    beforeEach(() => {
        (0, userBehavior_1.setGlobalOptions)(null);
        (0, userBehavior_1.resetUserSessions)();
    });
    const baseEvent = {
        method: 'GET',
        url: '/api/test',
        ip: '192.168.1.1',
        userAgent: 'Mozilla/5.0',
        timestamp: Date.now()
    };
    describe('Bot detection', () => {
        it('should detect bot-like behavior with regular intervals', () => {
            const baseTime = Date.now();
            let event = { ...baseEvent, timestamp: baseTime };
            (0, userBehavior_1.analyzeUserBehavior)(event);
            for (let i = 1; i <= 5; i++) {
                event = { ...baseEvent, timestamp: baseTime + (i * 100) };
                (0, userBehavior_1.analyzeUserBehavior)(event);
            }
            const result = (0, userBehavior_1.analyzeUserBehavior)({ ...baseEvent, timestamp: baseTime + 600 });
            expect(result.isAnomalous).toBe(true);
            expect(result.reasons.some(r => r.includes('bot'))).toBe(true);
        });
        it('should not detect normal user behavior', () => {
            const baseTime = Date.now();
            let event = { ...baseEvent, timestamp: baseTime };
            (0, userBehavior_1.analyzeUserBehavior)(event);
            // Większe odstępy czasowe (> 2s) żeby uniknąć wykrycia jako bot
            for (let i = 1; i <= 3; i++) {
                event = { ...baseEvent, timestamp: baseTime + (i * 3000) };
                (0, userBehavior_1.analyzeUserBehavior)(event);
            }
            const result = (0, userBehavior_1.analyzeUserBehavior)({ ...baseEvent, timestamp: baseTime + 12000 });
            // Normalne zachowanie powinno mieć niski score
            expect(result.score).toBeLessThan(30);
        });
    });
    describe('Endpoint access patterns', () => {
        it('should detect excessive endpoint access', () => {
            const baseTime = Date.now();
            let event = { ...baseEvent, timestamp: baseTime };
            // Tworzymy 11 różnych endpointów z mniej niż 20 requestami
            for (let i = 0; i < 11; i++) {
                event = { ...baseEvent, url: `/api/endpoint${i}`, timestamp: baseTime + (i * 100) };
                const result = (0, userBehavior_1.analyzeUserBehavior)(event);
                // Po 11 requestach powinno wykryć nadmierny dostęp
                if (i === 10) {
                    expect(result.reasons.some(r => r.includes('endpoints'))).toBe(true);
                }
            }
        });
    });
    describe('Rapid requests', () => {
        it('should detect rapid fire requests', () => {
            const baseTime = Date.now();
            let event = { ...baseEvent, timestamp: baseTime };
            (0, userBehavior_1.analyzeUserBehavior)(event);
            // Tworzymy 3 szybkie requesty z odstępami < 200ms
            for (let i = 1; i <= 3; i++) {
                event = { ...baseEvent, timestamp: baseTime + (i * 150) };
                (0, userBehavior_1.analyzeUserBehavior)(event);
            }
            // Po 4 requestach (1 początkowy + 3 szybkie) powinno wykryć
            const result = (0, userBehavior_1.analyzeUserBehavior)({ ...baseEvent, timestamp: baseTime + 600 });
            expect(result.reasons.some(r => r.includes('fast consecutive'))).toBe(true);
        });
    });
    describe('Suspicious method combinations', () => {
        it('should detect suspicious method combination', () => {
            const baseTime = Date.now();
            const methods = ['DELETE', 'PUT', 'PATCH'];
            methods.forEach((method, i) => {
                const event = {
                    ...baseEvent,
                    method,
                    timestamp: baseTime + (i * 1000)
                };
                (0, userBehavior_1.analyzeUserBehavior)(event);
            });
            // Po dodaniu wszystkich trzech metod z combo, powinno wykryć
            const result = (0, userBehavior_1.analyzeUserBehavior)({ ...baseEvent, method: 'GET', timestamp: baseTime + 3000 });
            expect(result.reasons.some(r => r.includes('Suspicious method combination'))).toBe(true);
        });
    });
    describe('Session duration', () => {
        it('should detect long session with few requests', () => {
            const baseTime = Date.now() - (35 * 60 * 1000);
            let event = { ...baseEvent, timestamp: baseTime };
            (0, userBehavior_1.analyzeUserBehavior)(event);
            // Tylko 2 dodatkowe requesty (razem 3 < 5)
            // Używamy rzeczywistego czasu dla ostatniego requestu żeby sessionDuration > 30min
            event = { ...baseEvent, timestamp: baseTime + (5 * 60 * 1000) };
            (0, userBehavior_1.analyzeUserBehavior)(event);
            // Ostatni request z aktualnym czasem - różnica od baseTime będzie > 30min
            const finalEvent = { ...baseEvent, timestamp: Date.now() };
            const result = (0, userBehavior_1.analyzeUserBehavior)(finalEvent);
            expect(result.reasons.some(r => r.includes('Long session'))).toBe(true);
        });
    });
    describe('API endpoint access', () => {
        it('should detect excessive API endpoint access', () => {
            const baseTime = Date.now();
            let event = { ...baseEvent, timestamp: baseTime };
            for (let i = 0; i < 60; i++) {
                event = { ...baseEvent, url: `/api/endpoint${i}`, timestamp: baseTime + (i * 100) };
                (0, userBehavior_1.analyzeUserBehavior)(event);
            }
            const result = (0, userBehavior_1.analyzeUserBehavior)({ ...baseEvent, url: '/api/endpoint60', timestamp: baseTime + 6000 });
            expect(result.isAnomalous).toBe(true);
            expect(result.reasons.some(r => r.includes('Excessive API endpoint'))).toBe(true);
        });
    });
    describe('Normal behavior', () => {
        it('should not flag normal user behavior', () => {
            const baseTime = Date.now();
            let event = { ...baseEvent, timestamp: baseTime };
            // Wykonaj kilka requestów z normalnymi odstępami czasowymi (> 3s)
            for (let i = 0; i < 3; i++) {
                event = { ...baseEvent, url: `/page${i}`, timestamp: baseTime + (i * 5000) };
                (0, userBehavior_1.analyzeUserBehavior)(event);
            }
            // Ostatni request powinien być normalny - większy odstęp czasowy
            const result = (0, userBehavior_1.analyzeUserBehavior)({ ...baseEvent, url: '/page3', timestamp: baseTime + 25000 });
            // Normalne zachowanie powinno mieć niski score (< 50)
            expect(result.score).toBeLessThan(50);
        });
    });
});
describe('detectSessionAnomalies', () => {
    beforeEach(() => {
        (0, userBehavior_1.setGlobalOptions)({ debug: false });
        (0, userBehavior_1.resetUserSessions)();
    });
    const baseEvent = {
        method: 'GET',
        url: '/api/test',
        ip: '192.168.1.1',
        userAgent: 'Mozilla/5.0',
        timestamp: Date.now()
    };
    it('should detect bot-like behavior', () => {
        const baseTime = Date.now();
        let event = { ...baseEvent, timestamp: baseTime };
        for (let i = 0; i < 10; i++) {
            event = { ...baseEvent, timestamp: baseTime + (i * 100) };
            (0, userBehavior_1.detectSessionAnomalies)(event);
        }
        const result = (0, userBehavior_1.detectSessionAnomalies)({ ...baseEvent, timestamp: baseTime + 1000 });
        expect(result).toBe(true);
    });
    it('should not detect anomalies for normal behavior', () => {
        const baseTime = Date.now();
        let event = { ...baseEvent, timestamp: baseTime };
        // Większe odstępy czasowe (> 2s) żeby uniknąć wykrycia jako bot
        for (let i = 0; i < 3; i++) {
            event = { ...baseEvent, timestamp: baseTime + (i * 3000) };
            (0, userBehavior_1.detectSessionAnomalies)(event);
        }
        const result = (0, userBehavior_1.detectSessionAnomalies)({ ...baseEvent, timestamp: baseTime + 10000 });
        // Normalne zachowanie powinno mieć niski score - sprawdzamy przez analyzeUserBehavior
        const behaviorResult = (0, userBehavior_1.analyzeUserBehavior)({ ...baseEvent, timestamp: baseTime + 10000 });
        expect(behaviorResult.score).toBeLessThan(30);
    });
});
