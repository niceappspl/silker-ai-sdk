"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const audit_1 = require("../../src/monitoring/audit");
describe('logAuditEvent', () => {
    beforeEach(() => {
        (0, audit_1.setGlobalOptions)(null);
        (0, audit_1.clearAuditLogs)();
    });
    const baseEvent = {
        method: 'GET',
        url: '/api/test',
        ip: '127.0.0.1',
        timestamp: Date.now()
    };
    it('should log audit event', () => {
        (0, audit_1.logAuditEvent)(baseEvent, 'blocked', 'Test block', 'high');
        const logs = (0, audit_1.getAuditLogs)(10);
        expect(logs.length).toBeGreaterThan(0);
        expect(logs[logs.length - 1].action).toBe('blocked');
        expect(logs[logs.length - 1].reason).toBe('Test block');
        expect(logs[logs.length - 1].severity).toBe('high');
    });
    it('should log with default severity', () => {
        (0, audit_1.logAuditEvent)(baseEvent, 'allowed', 'Test allow');
        const logs = (0, audit_1.getAuditLogs)(10);
        expect(logs[logs.length - 1].severity).toBe('low');
    });
    it('should log with all severity levels', () => {
        const severities = ['low', 'medium', 'high', 'critical'];
        severities.forEach(severity => {
            (0, audit_1.logAuditEvent)(baseEvent, 'flagged', `Test ${severity}`, severity);
        });
        const logs = (0, audit_1.getAuditLogs)(10);
        expect(logs.length).toBeGreaterThanOrEqual(4);
    });
    it('should log with metadata', () => {
        const metadata = { userId: '123', reason: 'custom' };
        (0, audit_1.logAuditEvent)(baseEvent, 'blocked', 'Test', 'high', metadata);
        const logs = (0, audit_1.getAuditLogs)(10);
        expect(logs[logs.length - 1].metadata).toEqual(metadata);
    });
    it('should enforce max logs limit', () => {
        for (let i = 0; i < 1001; i++) {
            (0, audit_1.logAuditEvent)({ ...baseEvent, url: `/api/test${i}` }, 'allowed', `Test ${i}`);
        }
        const logs = (0, audit_1.getAuditLogs)(1000);
        expect(logs.length).toBeLessThanOrEqual(1000);
    });
    it('should generate unique IDs', () => {
        (0, audit_1.logAuditEvent)(baseEvent, 'blocked', 'Test 1');
        (0, audit_1.logAuditEvent)(baseEvent, 'blocked', 'Test 2');
        const logs = (0, audit_1.getAuditLogs)(10);
        expect(logs[logs.length - 1].id).not.toBe(logs[logs.length - 2].id);
    });
});
describe('getAuditLogs', () => {
    beforeEach(() => {
        (0, audit_1.clearAuditLogs)();
        const baseEvent = {
            method: 'GET',
            url: '/api/test',
            ip: '127.0.0.1',
            timestamp: Date.now()
        };
        (0, audit_1.logAuditEvent)(baseEvent, 'blocked', 'Critical block', 'critical');
        (0, audit_1.logAuditEvent)(baseEvent, 'blocked', 'High block', 'high');
        (0, audit_1.logAuditEvent)(baseEvent, 'allowed', 'Low allow', 'low');
        (0, audit_1.logAuditEvent)(baseEvent, 'flagged', 'Medium flag', 'medium');
    });
    it('should return all logs without filters', () => {
        const logs = (0, audit_1.getAuditLogs)(100);
        expect(logs.length).toBeGreaterThan(0);
    });
    it('should filter by severity', () => {
        const logs = (0, audit_1.getAuditLogs)(100, 'critical');
        expect(logs.every(log => log.severity === 'critical')).toBe(true);
    });
    it('should filter by action', () => {
        const logs = (0, audit_1.getAuditLogs)(100, undefined, 'blocked');
        expect(logs.every(log => log.action === 'blocked')).toBe(true);
    });
    it('should filter by both severity and action', () => {
        const logs = (0, audit_1.getAuditLogs)(100, 'high', 'blocked');
        expect(logs.every(log => log.severity === 'high' && log.action === 'blocked')).toBe(true);
    });
    it('should respect limit parameter', () => {
        for (let i = 0; i < 20; i++) {
            const event = {
                method: 'GET',
                url: `/api/test${i}`,
                ip: '127.0.0.1',
                timestamp: Date.now()
            };
            (0, audit_1.logAuditEvent)(event, 'allowed', `Test ${i}`);
        }
        const logs = (0, audit_1.getAuditLogs)(10);
        expect(logs.length).toBeLessThanOrEqual(10);
    });
    it('should return empty array when no logs match filter', () => {
        const logs = (0, audit_1.getAuditLogs)(100, 'critical', 'allowed');
        expect(logs.length).toBe(0);
    });
    it('should return most recent logs', () => {
        const event1 = {
            method: 'GET',
            url: '/api/test1',
            ip: '127.0.0.1',
            timestamp: Date.now()
        };
        const event2 = {
            method: 'GET',
            url: '/api/test2',
            ip: '127.0.0.1',
            timestamp: Date.now() + 1000
        };
        (0, audit_1.logAuditEvent)(event1, 'allowed', 'First');
        (0, audit_1.logAuditEvent)(event2, 'allowed', 'Second');
        const logs = (0, audit_1.getAuditLogs)(2);
        expect(logs[logs.length - 1].event.url).toBe('/api/test2');
    });
});
describe('getAuditSummary', () => {
    beforeEach(() => {
        (0, audit_1.clearAuditLogs)();
        const baseEvent = {
            method: 'GET',
            url: '/api/test',
            ip: '127.0.0.1',
            timestamp: Date.now()
        };
        (0, audit_1.logAuditEvent)(baseEvent, 'blocked', 'Critical', 'critical');
        (0, audit_1.logAuditEvent)(baseEvent, 'blocked', 'High', 'high');
        (0, audit_1.logAuditEvent)(baseEvent, 'allowed', 'Low', 'low');
        (0, audit_1.logAuditEvent)(baseEvent, 'flagged', 'Medium', 'medium');
        (0, audit_1.logAuditEvent)(baseEvent, 'allowed', 'Low 2', 'low');
    });
    it('should generate audit summary', () => {
        const summary = (0, audit_1.getAuditSummary)();
        expect(summary.totalLogs).toBeGreaterThan(0);
        expect(summary.severityBreakdown).toBeDefined();
        expect(summary.actionBreakdown).toBeDefined();
        expect(summary.recentActivity).toBeDefined();
    });
    it('should calculate severity breakdown correctly', () => {
        const summary = (0, audit_1.getAuditSummary)();
        expect(summary.severityBreakdown.low).toBeGreaterThan(0);
        expect(summary.severityBreakdown.medium).toBeGreaterThan(0);
        expect(summary.severityBreakdown.high).toBeGreaterThan(0);
        expect(summary.severityBreakdown.critical).toBeGreaterThan(0);
    });
    it('should calculate action breakdown correctly', () => {
        const summary = (0, audit_1.getAuditSummary)();
        expect(summary.actionBreakdown.blocked).toBeGreaterThan(0);
        expect(summary.actionBreakdown.allowed).toBeGreaterThan(0);
        expect(summary.actionBreakdown.flagged).toBeGreaterThan(0);
    });
    it('should include recent activity', () => {
        const summary = (0, audit_1.getAuditSummary)();
        expect(summary.recentActivity.length).toBeGreaterThan(0);
        expect(summary.recentActivity.length).toBeLessThanOrEqual(10);
    });
    it('should have correct total logs count', () => {
        const summary = (0, audit_1.getAuditSummary)();
        const totalFromBreakdown = summary.severityBreakdown.low +
            summary.severityBreakdown.medium +
            summary.severityBreakdown.high +
            summary.severityBreakdown.critical;
        expect(summary.totalLogs).toBe(totalFromBreakdown);
    });
});
