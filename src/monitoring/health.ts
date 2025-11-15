import { HealthStatus } from '../types';
import { getPerformanceReport } from '../analytics/performance';
import { getAuditLogs } from './audit';

/**
 * Wykonuje sprawdzenie zdrowia systemu Silker.
 * Weryfikuje pamięć, wydajność, bezpieczeństwo i łączność z chmurą.
 * @returns Status zdrowia systemu
 */
export function performHealthCheck(): HealthStatus {
  const now = Date.now();
  const startTime = (global as any).silkerStartTime || now;

  const memUsage = process.memoryUsage();
  const memoryMB = memUsage.heapUsed / 1024 / 1024;
  const memoryStatus = memoryMB > 500 ? 'warning' : memoryMB > 1000 ? 'error' : 'ok';

  const perfReport = getPerformanceReport();
  const avgResponseTime = perfReport.summary.averageResponseTime;
  const perfStatus = avgResponseTime > 5000 ? 'error' : avgResponseTime > 2000 ? 'warning' : 'ok';

  const oneHourAgo = now - (60 * 60 * 1000);
  const recentBlocks = getAuditLogs(10000).filter(log =>
    log.timestamp > oneHourAgo && log.action === 'blocked'
  ).length;
  const securityStatus = recentBlocks > 100 ? 'warning' : recentBlocks > 500 ? 'error' : 'ok';

  const lastCloudContact = (global as any).lastCloudContact || 0;
  const timeSinceLastContact = now - lastCloudContact;
  const connectivityStatus = timeSinceLastContact > 300000 ? 'error' : 'ok';

  const statuses = [memoryStatus, perfStatus, securityStatus, connectivityStatus];
  const overallStatus = statuses.includes('error') ? 'unhealthy' :
                       statuses.includes('warning') ? 'degraded' : 'healthy';

  return {
    status: overallStatus,
    timestamp: now,
    checks: {
      memory: { status: memoryStatus, usage: Math.round(memoryMB) },
      performance: { status: perfStatus, avgResponseTime },
      security: { status: securityStatus, recentBlocks },
      connectivity: { status: connectivityStatus, lastCloudContact }
    },
    uptime: now - startTime,
    version: '0.1.0'
  };
}

