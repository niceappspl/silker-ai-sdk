import { EventEmitter } from 'events';
import { SilkerOptions, SilkerFeatures, SilkerEvent } from './types';
import { SilkerError } from './types/errors';
import { isAnomaly, setGlobalOptions as setDetectionOptions } from './detection';
import { setGlobalOptions as setAnalyticsOptions } from './analytics/userBehavior';
import { setGlobalOptions as setAuditOptions } from './monitoring/audit';
import { setGlobalOptions as setConfigOptions } from './config/runtime';
import { sendAlertToDashboard, sendThreatToDashboard, sendRequestToDashboard } from './cloud/dashboard';
import { detectThreatType, setGlobalOptionsForThreat } from './detection/threatDetection';
import { hookFetch } from './hooks/fetch';
import { hookExpress, getVibeEmitter } from './hooks/express';
import { getPerformanceReport, recordPerformanceMetrics } from './analytics/performance';
import { getAuditLogs, getAuditSummary, logAuditEvent } from './monitoring/audit';
import { getRuntimeConfig, updateRuntimeConfig } from './config';
import { performHealthCheck } from './monitoring/health';
import { performApiValidation } from './validation/apiSchema';
import { validateSecurityHeaders } from './validation/securityHeaders';
import { analyzeUserBehavior } from './analytics/userBehavior';
import { createLogger } from './utils/logger';

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
 * Waliduje opcje konfiguracyjne Silker AI.
 * @param options - Opcje do walidacji
 * @throws {SilkerError} Jeśli opcje są niepoprawne
 */
function validateOptions(options: SilkerOptions): void {
    if (!options || typeof options !== 'object') {
        throw new SilkerError('SilkerOptions are required and must be an object', 'INVALID_OPTIONS');
    }

    if (options.maxPayloadSize !== undefined) {
        if (typeof options.maxPayloadSize !== 'number' || options.maxPayloadSize < 0) {
            // Don't throw, just warn and correct to default to avoid crashing app on minor config error
             console.warn('⚠️ [Silker SDK] Invalid maxPayloadSize provided. Using default (50KB).');
             delete options.maxPayloadSize; // Will fall back to default in logic
        }
    }

    if (options.debug !== undefined && typeof options.debug !== 'boolean') {
        console.warn('⚠️ [Silker SDK] Invalid debug option provided. Disabling debug mode.');
        options.debug = false;
    }
}


/**
 * Inicjalizuje Silker AI z podanymi opcjami.
 * Weryfikuje połączenie z chmurą, konfiguruje hooki dla fetch i Express,
 * oraz uruchamia tryb proxy jeśli jest włączony.
 * @param options - Opcje konfiguracyjne Silker AI
 * @throws {SilkerError} Jeśli brakuje klucza API lub połączenie z chmurą nie powiodło się
 */
async function initSilker(options: SilkerOptions): Promise<void> {
  validateOptions(options);

  const logger = createLogger(options);
  const apiKey = options.apiKey || process.env.SILKER_API_KEY;
  
  if (!apiKey) {
    throw new SilkerError(
      'API key required. Provide it via options.apiKey or SILKER_API_KEY environment variable.',
      'MISSING_API_KEY'
    );
  }

  // Ensure maxPayloadSize has a safe default if not provided or deleted by validation
  if (!options.maxPayloadSize) {
      options.maxPayloadSize = 51200; // 50KB
  }

  const optionsWithApiKey = { ...options, apiKey };

  setGlobalOptions(options);

  (global as any).silkerStartTime = Date.now();

  if (options.features?.cloudCommunication !== false && options.appId) {
    const testEvent: SilkerEvent = {
      method: 'GET',
      url: '/silker/test',
      timestamp: Date.now(),
      ip: '127.0.0.1',
      userAgent: 'Silker-AI-SDK/Test',
      headers: {}
    };

    try {
      setGlobalOptionsForThreat(options);
      const threatInfo = detectThreatType(testEvent);
      if (threatInfo) {
        await sendAlertToDashboard(testEvent, threatInfo.type, threatInfo.severity, options);
      }
    } catch (error) {
      logger.warn('⚠️ Dashboard connection test failed, but continuing...');
    }
  }

  logger.info('Silker AI initialized successfully');

  hookFetch(options);

  const vibeEmitter = getVibeEmitter();
  vibeEmitter.on('request', async (event: SilkerEvent) => {
    // Send request to dashboard
    if (options.features?.cloudCommunication !== false && options.appId) {
      // Default response values if not provided in event (since middleware might not capture response end yet)
      // TODO: Implement response capture in middleware
      sendRequestToDashboard(event, 200, 0, options);
    }
  });

  vibeEmitter.on('workflow', async (event: SilkerEvent) => {
    if (isAnomaly(event)) {
      if (options.features?.cloudCommunication !== false && options.appId) {
        setGlobalOptionsForThreat(options);
        const threatInfo = detectThreatType(event);
        if (threatInfo) {
          await sendAlertToDashboard(
            event,
            threatInfo.type,
            threatInfo.severity,
            options
          );
          
          await sendThreatToDashboard(
            event,
            threatInfo.type,
            threatInfo.severity,
            true,
            threatInfo.description,
            options
          );

          logger.debug('Workflow anomaly detected and reported:', event.url);
        }
      }
    }
  });

  (global as any).silkerEmitter = vibeEmitter;
}

/**
 * Emituje zdarzenie workflow do systemu monitorowania Silker AI.
 * @param event - Zdarzenie workflow bez znacznika czasu (timestamp zostanie dodany automatycznie)
 */
function emitSilkerWorkflowEvent(event: Omit<SilkerEvent, 'timestamp'>) {
  const vibeEmitter = getVibeEmitter();
  vibeEmitter.emit('workflow', { ...event, timestamp: Date.now() });
}


export const middleware = hookExpress;

const SilkerAI = {
  init: initSilker,
  emitWorkflowEvent: emitSilkerWorkflowEvent,
  middleware: hookExpress,
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
  SilkerError
};

export type {
  SilkerOptions,
  SilkerFeatures,
  SilkerEvent,
};
