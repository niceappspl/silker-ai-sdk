import { SilkerEvent, SilkerOptions } from '../types';
import { isAnomaly, setGlobalOptions } from '../detection';
import { sendThreatToDashboard, sendRequestToDashboard } from '../cloud/dashboard';
import { detectThreatType, setGlobalOptionsForThreat } from '../detection/threatDetection';
import { logAuditEvent } from '../monitoring/audit';
import { createLogger } from '../utils/logger';
import { recordPerformanceMetrics } from '../analytics/performance';

let globalOptions: SilkerOptions | null = null;
let originalFetchBackup: typeof global.fetch | null = null;

/**
 * Resetuje stan fetch hook.
 * TYLKO DO UŻYTKU W TESTACH!
 * @internal
 */
export function resetFetchHook(): void {
  if (originalFetchBackup) {
    global.fetch = originalFetchBackup;
    originalFetchBackup = null;
  }
}

/**
 * Bezpieczna serializacja do JSON z obsługą circular references i błędów.
 */
function safeStringify(obj: any): string {
  try {
    return JSON.stringify(obj);
  } catch (e) {
    return '[Unserializable Body]';
  }
}

/**
 * Przechwytuje globalną funkcję fetch i dodaje monitorowanie bezpieczeństwa.
 * Wszystkie wywołania fetch są sprawdzane pod kątem anomalii przed wykonaniem.
 * @param options - Opcje konfiguracyjne Silker
 */
export function hookFetch(options: SilkerOptions) {
  try {
    if (originalFetchBackup !== null) {
      return;
    }

    globalOptions = options;
    setGlobalOptions(options);
    const logger = createLogger(options);

    originalFetchBackup = global.fetch;

    global.fetch = async function (input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const start = Date.now();
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const method = init?.method || 'GET';

    const ip = (global as any).request?.ip || (global as any).req?.connection?.remoteAddress;

    const event: SilkerEvent = {
      method,
      url,
      payload: init?.body
        ? (typeof init.body === 'string' ? init.body : safeStringify(init.body))
        : undefined,
      ip,
      timestamp: start,
      userAgent: (init?.headers as any)?.['User-Agent'],
      headers: init?.headers as Record<string, string>
    };

    if (isAnomaly(event)) {
      logger.debug('Anomaly detected, blocking request');

      const isAuditEnabled = options.features?.auditLogging !== false;
      if (isAuditEnabled) {
        logAuditEvent(event, 'flagged', 'Security anomaly detected', 'high');
      }

      if (options.features?.cloudCommunication !== false && options.appId) {
        setGlobalOptionsForThreat(options);
        const threatInfo = detectThreatType(event);
        if (threatInfo) {
          try {
            await sendThreatToDashboard(
              event,
              threatInfo.type,
              threatInfo.severity,
              true,
              threatInfo.description,
              options,
              Date.now() - start
            );
          } catch (err) {
            // Ignore dashboard error
          }

          if (isAuditEnabled) {
            logAuditEvent(event, 'blocked', `Threat blocked: ${threatInfo.type}`, 'critical');
          }

          return new Response(JSON.stringify({
            error: 'Request blocked by Silker AI',
            reason: 'Security threat detected',
            type: threatInfo.type
          }), {
            status: 403,
            headers: { 'Content-Type': 'application/json' }
          });
        }
      }

      if (isAuditEnabled) {
        logAuditEvent(event, 'blocked', 'Security anomaly detected', 'high');
      }

      return new Response(JSON.stringify({
        error: 'Request blocked by Silker AI',
        reason: 'Security threat detected'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    } else {
      if (options.features?.auditLogging !== false) {
        logAuditEvent(event, 'allowed', 'Request passed security checks', 'low');
      }
    }

    try {
        const response = await originalFetchBackup!.call(this, input, init);
        const duration = Date.now() - start;
        
        // Record performance metrics
        recordPerformanceMetrics(event, duration, response.status);

        // Send request metrics to dashboard if enabled
        if (options.features?.cloudCommunication !== false && options.appId) {
            try {
                await sendRequestToDashboard(event, response.status, duration, options);
            } catch (err) {
                // Ignore
            }
        }

        return response;
    } catch (error) {
        const duration = Date.now() - start;
        recordPerformanceMetrics(event, duration, 0); // 0 status for error
        throw error;
    }
    };
  } catch (error) {
    const logger = createLogger(options);
    logger.error('[Silker SDK] Critical error hooking fetch. Fetch will work normally without security monitoring:', error);
  }
}

