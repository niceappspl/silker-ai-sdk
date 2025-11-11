import { EventEmitter } from 'events';
import { VibeGuardOptions, VibeGuardEvent, CloudResponse } from './types';
import { VibeGuardError } from './types/errors';
import { isAnomaly, setGlobalOptions as setDetectionOptions } from './detection';
import { setGlobalOptions as setAnalyticsOptions } from './analytics/userBehavior';
import { setGlobalOptions as setAuditOptions } from './monitoring/audit';
import { setGlobalOptions as setConfigOptions } from './config/runtime';
import { sendToCloud } from './cloud';
import { hookFetch } from './hooks/fetch';
import { hookExpress, getVibeEmitter } from './hooks/express';
import { startProxyMode } from './hooks/proxy';
import { getPerformanceReport, recordPerformanceMetrics } from './analytics/performance';
import { getAuditLogs, getAuditSummary, logAuditEvent } from './monitoring/audit';
import { getRuntimeConfig, updateRuntimeConfig } from './config';
import { performHealthCheck } from './monitoring/health';

/**
 * Ustawia globalne opcje dla wszystkich modułów VibeGuard.
 * @param options - Opcje konfiguracyjne VibeGuard lub null
 */
function setGlobalOptions(options: VibeGuardOptions | null) {
  setDetectionOptions(options);
  setAnalyticsOptions(options);
  setAuditOptions(options);
  setConfigOptions(options);
}

/**
 * Inicjalizuje VibeGuard z podanymi opcjami.
 * Weryfikuje połączenie z chmurą, konfiguruje hooki dla fetch i Express,
 * oraz uruchamia tryb proxy jeśli jest włączony.
 * @param options - Opcje konfiguracyjne VibeGuard
 * @throws {VibeGuardError} Jeśli brakuje klucza API lub połączenie z chmurą nie powiodło się
 */
export async function initVibeGuard(options: VibeGuardOptions): Promise<void> {
  if (!options.apiKey) {
    throw new VibeGuardError('API key required', 'MISSING_API_KEY');
  }

  setGlobalOptions(options);

  (global as any).vibeGuardStartTime = Date.now();

  const testEvent: VibeGuardEvent = {
    method: 'GET',
    url: '/vibeguard/test',
    timestamp: Date.now()
  };

  const response = await sendToCloud(testEvent, options);
  if (response === null) {
    throw new VibeGuardError('Failed to connect to VibeGuard cloud', 'CONNECTION_FAILED');
  }

  if (options.debug) {
    console.log('✨ VibeGuard initialized successfully!');
  }

  hookFetch(options);

  const vibeEmitter = getVibeEmitter();
  vibeEmitter.on('workflow', async (event: VibeGuardEvent) => {
    if (isAnomaly(event)) {
      const cloudResponse = await sendToCloud(event, options);
      if (cloudResponse?.block && options.debug) {
        console.log('🚫 Workflow anomaly blocked:', event.url);
      }
    }
  });

  (global as any).vibeGuardEmitter = vibeEmitter;

  if (options.proxyMode) {
    const targetUrl = process.env.VIBEGUARD_TARGET_URL || 'http://localhost:3000';
    const proxyPort = parseInt(process.env.VIBEGUARD_PROXY_PORT || '8080');
    startProxyMode(options, targetUrl, proxyPort);
  }
}

/**
 * Emituje zdarzenie workflow do systemu monitorowania VibeGuard.
 * @param event - Zdarzenie workflow bez znacznika czasu (timestamp zostanie dodany automatycznie)
 */
export function emitWorkflowEvent(event: Omit<VibeGuardEvent, 'timestamp'>) {
  const vibeEmitter = getVibeEmitter();
  vibeEmitter.emit('workflow', { ...event, timestamp: Date.now() });
}

export const middleware = hookExpress;

export {
  sendToCloud,
  getPerformanceReport,
  recordPerformanceMetrics,
  getAuditLogs,
  getAuditSummary,
  logAuditEvent,
  getRuntimeConfig,
  updateRuntimeConfig,
  performHealthCheck,
  VibeGuardError
};

export type {
  VibeGuardOptions,
  VibeGuardEvent,
  CloudResponse
};
