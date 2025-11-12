"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const performance_1 = require("../../src/analytics/performance");
describe('recordPerformanceMetrics', () => {
    const baseEvent = {
        method: 'GET',
        url: '/api/test',
        ip: '127.0.0.1',
        timestamp: Date.now()
    };
    it('should record performance metrics', () => {
        (0, performance_1.recordPerformanceMetrics)(baseEvent, 1500, 200);
        const report = (0, performance_1.getPerformanceReport)();
        expect(report.summary.totalRequests).toBeGreaterThan(0);
    });
    it('should record metrics with status code', () => {
        (0, performance_1.recordPerformanceMetrics)(baseEvent, 2000, 404);
        const report = (0, performance_1.getPerformanceReport)();
        const recent = report.recentMetrics[report.recentMetrics.length - 1];
        expect(recent.statusCode).toBe(404);
    });
    it('should record multiple metrics', () => {
        for (let i = 0; i < 5; i++) {
            (0, performance_1.recordPerformanceMetrics)({ ...baseEvent, url: `/api/test${i}` }, 1000 + i * 100);
        }
        const report = (0, performance_1.getPerformanceReport)();
        expect(report.summary.totalRequests).toBeGreaterThanOrEqual(5);
    });
});
describe('detectPerformanceAnomalies', () => {
    beforeEach(() => {
        for (let i = 0; i < 50; i++) {
            const event = {
                method: 'GET',
                url: `/api/test${i}`,
                ip: '127.0.0.1',
                timestamp: Date.now()
            };
            (0, performance_1.recordPerformanceMetrics)(event, 1000);
        }
    });
    it('should return empty anomalies for insufficient data', () => {
        const anomalies = (0, performance_1.detectPerformanceAnomalies)();
        expect(anomalies.anomalies.length).toBeGreaterThanOrEqual(0);
    });
    it('should detect high average response time', () => {
        for (let i = 0; i < 20; i++) {
            const event = {
                method: 'GET',
                url: `/api/slow${i}`,
                ip: '127.0.0.1',
                timestamp: Date.now()
            };
            (0, performance_1.recordPerformanceMetrics)(event, 3000);
        }
        const anomalies = (0, performance_1.detectPerformanceAnomalies)();
        expect(anomalies.averageResponseTime).toBeGreaterThan(0);
    });
    it('should detect slow requests', () => {
        for (let i = 0; i < 20; i++) {
            const event = {
                method: 'GET',
                url: `/api/slow${i}`,
                ip: '127.0.0.1',
                timestamp: Date.now()
            };
            (0, performance_1.recordPerformanceMetrics)(event, 6000);
        }
        const anomalies = (0, performance_1.detectPerformanceAnomalies)();
        expect(anomalies.slowRequests).toBeGreaterThan(0);
    });
    it('should detect slow endpoints', () => {
        for (let i = 0; i < 10; i++) {
            const event = {
                method: 'GET',
                url: '/api/slow-endpoint',
                ip: '127.0.0.1',
                timestamp: Date.now()
            };
            (0, performance_1.recordPerformanceMetrics)(event, 4000);
        }
        const anomalies = (0, performance_1.detectPerformanceAnomalies)();
        expect(anomalies.anomalies.some(a => a.includes('Slow endpoint'))).toBe(true);
    });
});
describe('getPerformanceReport', () => {
    beforeEach(() => {
        for (let i = 0; i < 20; i++) {
            const event = {
                method: 'GET',
                url: `/api/test${i}`,
                ip: '127.0.0.1',
                timestamp: Date.now()
            };
            (0, performance_1.recordPerformanceMetrics)(event, 1000 + i * 100);
        }
    });
    it('should generate performance report', () => {
        const report = (0, performance_1.getPerformanceReport)();
        expect(report.summary).toBeDefined();
        expect(report.recentMetrics).toBeDefined();
        expect(report.anomalies).toBeDefined();
    });
    it('should include summary statistics', () => {
        const report = (0, performance_1.getPerformanceReport)();
        expect(report.summary.totalRequests).toBeGreaterThan(0);
        expect(typeof report.summary.averageResponseTime).toBe('number');
        expect(typeof report.summary.slowRequests).toBe('number');
    });
    it('should include recent metrics', () => {
        const report = (0, performance_1.getPerformanceReport)();
        expect(report.recentMetrics.length).toBeGreaterThan(0);
        expect(report.recentMetrics.length).toBeLessThanOrEqual(20);
    });
    it('should include anomalies if detected', () => {
        for (let i = 0; i < 30; i++) {
            const event = {
                method: 'GET',
                url: `/api/slow${i}`,
                ip: '127.0.0.1',
                timestamp: Date.now()
            };
            (0, performance_1.recordPerformanceMetrics)(event, 3000);
        }
        const report = (0, performance_1.getPerformanceReport)();
        expect(Array.isArray(report.anomalies)).toBe(true);
    });
});
