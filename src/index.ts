import { EventEmitter } from 'events';
import { SilkerOptions, SilkerFeatures, SilkerEvent } from './types';
import { SilkerError } from './types/errors';
import { isAnomaly, setGlobalOptions as setDetectionOptions } from './detection';
import { setGlobalOptions as setAnalyticsOptions } from './analytics/userBehavior';
import { setGlobalOptions as setAuditOptions } from './monitoring/audit';
import { setGlobalOptions as setConfigOptions } from './config/runtime';
import { sendThreatToDashboard, sendRequestToDashboard } from './cloud/dashboard';
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
import { createLogger, defaultLogger } from './utils/logger';
import { setRateLimitConfig } from './detection/rateLimit';
import { getSilkerState } from './utils/globalState';

let isInitialized = false;

/**
 * Resetuje stan inicjalizacji SDK.
 * TYLKO DO UŻYTKU W TESTACH - nie wywoływać w produkcji!
 * @internal
 */
export function resetSilkerState(): void {
  isInitialized = false;
}

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
 * @returns true jeśli opcje są poprawne, false w przeciwnym razie
 */
function validateOptions(options: SilkerOptions): boolean {
    if (!options || typeof options !== 'object') {
        defaultLogger.error('[Silker SDK] SilkerOptions are required and must be an object. SDK will not initialize.');
        return false;
    }

    const MAX_ALLOWED_PAYLOAD = 100 * 1024 * 1024; // 100MB

    if (options.maxPayloadSize !== undefined) {
        if (typeof options.maxPayloadSize !== 'number' || options.maxPayloadSize < 0) {
             defaultLogger.warn('[Silker SDK] Invalid maxPayloadSize provided. Using default (1MB).');
             delete options.maxPayloadSize;
        } else if (options.maxPayloadSize > MAX_ALLOWED_PAYLOAD) {
             defaultLogger.warn(`[Silker SDK] maxPayloadSize too large (${options.maxPayloadSize} bytes). Using maximum allowed: ${MAX_ALLOWED_PAYLOAD} bytes (100MB).`);
             options.maxPayloadSize = MAX_ALLOWED_PAYLOAD;
        }
    }

    if (options.debug !== undefined && typeof options.debug !== 'boolean') {
        defaultLogger.warn('[Silker SDK] Invalid debug option provided. Disabling debug mode.');
        options.debug = false;
    }

    return true;
}


/**
 * Inicjalizuje Silker AI z podanymi opcjami.
 * Weryfikuje połączenie z chmurą, konfiguruje hooki dla fetch i Express,
 * oraz uruchamia tryb proxy jeśli jest włączony.
 * @param options - Opcje konfiguracyjne Silker AI
 * @throws {SilkerError} Jeśli brakuje klucza API, połączenie z chmurą nie powiodło się lub SDK jest już zainicjalizowany
 */
async function initSilker(options: SilkerOptions): Promise<void> {
  try {
    if (isInitialized) {
      const logger = createLogger(options);
      logger.warn('[Silker SDK] SDK is already initialized. Skipping re-initialization.');
      return;
    }

    if (!validateOptions(options)) {
      return;
    }

    const logger = createLogger(options);
    const apiKey = options.apiKey || process.env.SILKER_API_KEY;
    
    if (!apiKey) {
      logger.error('[Silker SDK] API key required. SDK will not function without it. Provide via options.apiKey or SILKER_API_KEY environment variable.');
      return;
    }

    if (!/^sk_[a-zA-Z0-9_-]{32,}$/.test(apiKey)) {
      logger.error('[Silker SDK] Invalid API key format. Expected: sk_xxxxxxxxxxxxx (at least 32 characters). SDK will not function properly.');
      return;
    }

    if (!options.maxPayloadSize) {
        options.maxPayloadSize = 1048576; // 1MB
    }

    if (options.rateLimit) {
      setRateLimitConfig(options.rateLimit);
    }

    setGlobalOptions(options);
    setGlobalOptionsForThreat(options);

    const state = getSilkerState();
    state.startTime = Date.now();

    logger.info('Silker AI initialized successfully');

    hookFetch(options);

    const vibeEmitter = getVibeEmitter();
    vibeEmitter.on('workflow', async (event: SilkerEvent) => {
      try {
        if (isAnomaly(event)) {
          if (options.features?.cloudCommunication !== false && options.appId) {
            setGlobalOptionsForThreat(options);
            const threatInfo = detectThreatType(event);
            if (threatInfo) {
              await sendThreatToDashboard(
                event,
                threatInfo.type,
                threatInfo.severity,
                true,
                threatInfo.description,
                options,
                Date.now() - event.timestamp
              );

              logger.debug('Workflow anomaly detected and reported:', event.url);
            }
          }
        }
      } catch (error) {
        logger.error('[Silker SDK] Error processing workflow event:', error);
      }
    });

    state.emitter = vibeEmitter;
    
    isInitialized = true;
  } catch (error) {
    const logger = createLogger(options);
    logger.error('[Silker SDK] Critical error during initialization. SDK will not function:', error);
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
