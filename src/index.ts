import { EventEmitter } from 'events';
import { SilkerOptions, SilkerFeatures, SilkerEvent, VibeGuardOptions, VibeGuardFeatures, VibeGuardEvent, CloudResponse } from './types';
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
import { performApiValidation } from './validation/apiSchema';
import { validateSecurityHeaders } from './validation/securityHeaders';
import { analyzeUserBehavior } from './analytics/userBehavior';

/**
 * Ustawia globalne opcje dla wszystkich modułów Silker AI.
 * @param options - Opcje konfiguracyjne Silker AI lub null
 */
function setGlobalOptions(options: SilkerOptions | null) {
  setDetectionOptions(options);
  setAnalyticsOptions(options);
  setAuditOptions(options);
  setConfigOptions(options);
}

/**
 * Inicjalizuje Silker AI z podanymi opcjami.
 * Weryfikuje połączenie z chmurą, konfiguruje hooki dla fetch i Express,
 * oraz uruchamia tryb proxy jeśli jest włączony.
 * @param options - Opcje konfiguracyjne Silker AI
 * @throws {VibeGuardError} Jeśli brakuje klucza API lub połączenie z chmurą nie powiodło się
 */
async function initSilker(options: SilkerOptions): Promise<void> {
  const apiKey = options.apiKey || process.env.SILKER_API_KEY || process.env.VIBEGUARD_API_KEY;
  
  if (!apiKey) {
    throw new VibeGuardError(
      'API key required. Provide it via options.apiKey or SILKER_API_KEY environment variable.',
      'MISSING_API_KEY'
    );
  }

  const optionsWithApiKey = { ...options, apiKey };

  setGlobalOptions(options);

  (global as any).silkerStartTime = Date.now();
  (global as any).vibeGuardStartTime = Date.now();

  if (options.features?.cloudCommunication !== false) {
    const testEvent: SilkerEvent = {
      method: 'GET',
      url: '/silker/test',
      timestamp: Date.now()
    };

    const response = await sendToCloud(testEvent, options);
    if (response === null) {
      throw new VibeGuardError('Failed to connect to Silker AI cloud', 'CONNECTION_FAILED');
    }
  }

  if (options.debug) {
    console.log('Silker AI initialized successfully');
  }

  hookFetch(options);

  const vibeEmitter = getVibeEmitter();
  vibeEmitter.on('workflow', async (event: SilkerEvent) => {
    if (isAnomaly(event)) {
      const cloudResponse = options.features?.cloudCommunication !== false 
        ? await sendToCloud(event, options)
        : null;
      if (cloudResponse?.block && options.debug) {
        console.log('Workflow anomaly blocked:', event.url);
      }
    }
  });

  (global as any).silkerEmitter = vibeEmitter;
  (global as any).vibeGuardEmitter = vibeEmitter;

  if (options.proxyMode) {
    const targetUrl = process.env.SILKER_TARGET_URL || process.env.VIBEGUARD_TARGET_URL || 'http://localhost:3000';
    const proxyPort = parseInt(process.env.SILKER_PROXY_PORT || process.env.VIBEGUARD_PROXY_PORT || '8080');
    startProxyMode(options, targetUrl, proxyPort);
  }
}

/**
 * Emituje zdarzenie workflow do systemu monitorowania Silker AI.
 * @param event - Zdarzenie workflow bez znacznika czasu (timestamp zostanie dodany automatycznie)
 */
function emitSilkerWorkflowEvent(event: Omit<SilkerEvent, 'timestamp'>) {
  const vibeEmitter = getVibeEmitter();
  vibeEmitter.emit('workflow', { ...event, timestamp: Date.now() });
}

export async function initVibeGuard(options: VibeGuardOptions): Promise<void> {
  return initSilker(options);
}

export function emitWorkflowEvent(event: Omit<VibeGuardEvent, 'timestamp'>) {
  return emitSilkerWorkflowEvent(event);
}

export const middleware = hookExpress;

const SilkerAI = {
  init: initSilker,
  emitWorkflowEvent: emitSilkerWorkflowEvent,
  middleware: hookExpress,
  sendToCloud,
  getPerformanceReport,
  recordPerformanceMetrics,
  getAuditLogs,
  getAuditSummary,
  logAuditEvent,
  getRuntimeConfig,
  updateRuntimeConfig,
  performHealthCheck,
  performApiValidation,
  validateSecurityHeaders,
  analyzeUserBehavior
};

export default SilkerAI;

export {
  initSilker,
  emitSilkerWorkflowEvent,
  sendToCloud,
  getPerformanceReport,
  recordPerformanceMetrics,
  getAuditLogs,
  getAuditSummary,
  logAuditEvent,
  getRuntimeConfig,
  updateRuntimeConfig,
  performHealthCheck,
  performApiValidation,
  validateSecurityHeaders,
  analyzeUserBehavior,
  VibeGuardError
};

export type {
  SilkerOptions,
  SilkerFeatures,
  SilkerEvent,
  CloudResponse
};

export type { VibeGuardOptions, VibeGuardFeatures, VibeGuardEvent };
