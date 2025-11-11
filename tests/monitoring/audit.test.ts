import { logAuditEvent, getAuditLogs, getAuditSummary, setGlobalOptions, clearAuditLogs } from '../../src/monitoring/audit';
import { VibeGuardEvent } from '../../src/types';

describe('logAuditEvent', () => {
  beforeEach(() => {
    setGlobalOptions(null);
    clearAuditLogs();
  });

  const baseEvent: VibeGuardEvent = {
    method: 'GET',
    url: '/api/test',
    ip: '127.0.0.1',
    timestamp: Date.now()
  };

  it('should log audit event', () => {
    logAuditEvent(baseEvent, 'blocked', 'Test block', 'high');
    const logs = getAuditLogs(10);
    expect(logs.length).toBeGreaterThan(0);
    expect(logs[logs.length - 1].action).toBe('blocked');
    expect(logs[logs.length - 1].reason).toBe('Test block');
    expect(logs[logs.length - 1].severity).toBe('high');
  });

  it('should log with default severity', () => {
    logAuditEvent(baseEvent, 'allowed', 'Test allow');
    const logs = getAuditLogs(10);
    expect(logs[logs.length - 1].severity).toBe('low');
  });

  it('should log with all severity levels', () => {
    const severities: Array<'low' | 'medium' | 'high' | 'critical'> = ['low', 'medium', 'high', 'critical'];
    severities.forEach(severity => {
      logAuditEvent(baseEvent, 'flagged', `Test ${severity}`, severity);
    });
    const logs = getAuditLogs(10);
    expect(logs.length).toBeGreaterThanOrEqual(4);
  });

  it('should log with metadata', () => {
    const metadata = { userId: '123', reason: 'custom' };
    logAuditEvent(baseEvent, 'blocked', 'Test', 'high', metadata);
    const logs = getAuditLogs(10);
    expect(logs[logs.length - 1].metadata).toEqual(metadata);
  });

  it('should enforce max logs limit', () => {
    for (let i = 0; i < 1001; i++) {
      logAuditEvent({ ...baseEvent, url: `/api/test${i}` }, 'allowed', `Test ${i}`);
    }
    const logs = getAuditLogs(1000);
    expect(logs.length).toBeLessThanOrEqual(1000);
  });

  it('should generate unique IDs', () => {
    logAuditEvent(baseEvent, 'blocked', 'Test 1');
    logAuditEvent(baseEvent, 'blocked', 'Test 2');
    const logs = getAuditLogs(10);
    expect(logs[logs.length - 1].id).not.toBe(logs[logs.length - 2].id);
  });
});

describe('getAuditLogs', () => {
  beforeEach(() => {
    clearAuditLogs();
    
    const baseEvent: VibeGuardEvent = {
      method: 'GET',
      url: '/api/test',
      ip: '127.0.0.1',
      timestamp: Date.now()
    };

    logAuditEvent(baseEvent, 'blocked', 'Critical block', 'critical');
    logAuditEvent(baseEvent, 'blocked', 'High block', 'high');
    logAuditEvent(baseEvent, 'allowed', 'Low allow', 'low');
    logAuditEvent(baseEvent, 'flagged', 'Medium flag', 'medium');
  });

  it('should return all logs without filters', () => {
    const logs = getAuditLogs(100);
    expect(logs.length).toBeGreaterThan(0);
  });

  it('should filter by severity', () => {
    const logs = getAuditLogs(100, 'critical');
    expect(logs.every(log => log.severity === 'critical')).toBe(true);
  });

  it('should filter by action', () => {
    const logs = getAuditLogs(100, undefined, 'blocked');
    expect(logs.every(log => log.action === 'blocked')).toBe(true);
  });

  it('should filter by both severity and action', () => {
    const logs = getAuditLogs(100, 'high', 'blocked');
    expect(logs.every(log => log.severity === 'high' && log.action === 'blocked')).toBe(true);
  });

  it('should respect limit parameter', () => {
    for (let i = 0; i < 20; i++) {
      const event: VibeGuardEvent = {
        method: 'GET',
        url: `/api/test${i}`,
        ip: '127.0.0.1',
        timestamp: Date.now()
      };
      logAuditEvent(event, 'allowed', `Test ${i}`);
    }
    
    const logs = getAuditLogs(10);
    expect(logs.length).toBeLessThanOrEqual(10);
  });

  it('should return empty array when no logs match filter', () => {
    const logs = getAuditLogs(100, 'critical', 'allowed');
    expect(logs.length).toBe(0);
  });

  it('should return most recent logs', () => {
    const event1: VibeGuardEvent = {
      method: 'GET',
      url: '/api/test1',
      ip: '127.0.0.1',
      timestamp: Date.now()
    };
    const event2: VibeGuardEvent = {
      method: 'GET',
      url: '/api/test2',
      ip: '127.0.0.1',
      timestamp: Date.now() + 1000
    };
    
    logAuditEvent(event1, 'allowed', 'First');
    logAuditEvent(event2, 'allowed', 'Second');
    
    const logs = getAuditLogs(2);
    expect(logs[logs.length - 1].event.url).toBe('/api/test2');
  });
});

describe('getAuditSummary', () => {
  beforeEach(() => {
    clearAuditLogs();
    
    const baseEvent: VibeGuardEvent = {
      method: 'GET',
      url: '/api/test',
      ip: '127.0.0.1',
      timestamp: Date.now()
    };

    logAuditEvent(baseEvent, 'blocked', 'Critical', 'critical');
    logAuditEvent(baseEvent, 'blocked', 'High', 'high');
    logAuditEvent(baseEvent, 'allowed', 'Low', 'low');
    logAuditEvent(baseEvent, 'flagged', 'Medium', 'medium');
    logAuditEvent(baseEvent, 'allowed', 'Low 2', 'low');
  });

  it('should generate audit summary', () => {
    const summary = getAuditSummary();
    expect(summary.totalLogs).toBeGreaterThan(0);
    expect(summary.severityBreakdown).toBeDefined();
    expect(summary.actionBreakdown).toBeDefined();
    expect(summary.recentActivity).toBeDefined();
  });

  it('should calculate severity breakdown correctly', () => {
    const summary = getAuditSummary();
    expect(summary.severityBreakdown.low).toBeGreaterThan(0);
    expect(summary.severityBreakdown.medium).toBeGreaterThan(0);
    expect(summary.severityBreakdown.high).toBeGreaterThan(0);
    expect(summary.severityBreakdown.critical).toBeGreaterThan(0);
  });

  it('should calculate action breakdown correctly', () => {
    const summary = getAuditSummary();
    expect(summary.actionBreakdown.blocked).toBeGreaterThan(0);
    expect(summary.actionBreakdown.allowed).toBeGreaterThan(0);
    expect(summary.actionBreakdown.flagged).toBeGreaterThan(0);
  });

  it('should include recent activity', () => {
    const summary = getAuditSummary();
    expect(summary.recentActivity.length).toBeGreaterThan(0);
    expect(summary.recentActivity.length).toBeLessThanOrEqual(10);
  });

  it('should have correct total logs count', () => {
    const summary = getAuditSummary();
    const totalFromBreakdown = 
      summary.severityBreakdown.low +
      summary.severityBreakdown.medium +
      summary.severityBreakdown.high +
      summary.severityBreakdown.critical;
    expect(summary.totalLogs).toBe(totalFromBreakdown);
  });
});
