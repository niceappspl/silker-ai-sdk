import { SilkerEvent, SilkerOptions } from '../types';
import { isAnomaly, setGlobalOptions } from '../detection';
import { sendAlertToDashboard, sendThreatToDashboard } from '../cloud/dashboard';
import { detectThreatType, setGlobalOptionsForThreat } from '../detection/threatDetection';
import { logAuditEvent } from '../monitoring/audit';

let globalOptions: SilkerOptions | null = null;

/**
 * Przechwytuje globalną funkcję fetch i dodaje monitorowanie bezpieczeństwa.
 * Wszystkie wywołania fetch są sprawdzane pod kątem anomalii przed wykonaniem.
 * @param options - Opcje konfiguracyjne Silker
 */
export function hookFetch(options: SilkerOptions) {
  globalOptions = options;
  setGlobalOptions(options);

  const originalFetch = global.fetch;

  global.fetch = async function (input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const method = init?.method || 'GET';

    const ip = (global as any).request?.ip || (global as any).req?.connection?.remoteAddress;

    const event: SilkerEvent = {
      method,
      url,
      payload: init?.body ? JSON.stringify(init.body) : undefined,
      ip,
      timestamp: Date.now(),
      userAgent: (init?.headers as any)?.['User-Agent'],
      headers: init?.headers as Record<string, string>
    };

    if (isAnomaly(event)) {
      if (options.debug) {
        console.log('🚨 Anomaly detected, blocking request');
      }

      const isAuditEnabled = options.features?.auditLogging !== false;
      if (isAuditEnabled) {
        logAuditEvent(event, 'flagged', 'Security anomaly detected', 'high');
      }

      if (options.features?.cloudCommunication !== false && options.appId) {
        setGlobalOptionsForThreat(options);
        const threatInfo = detectThreatType(event);
        if (threatInfo) {
          sendAlertToDashboard(
            event,
            threatInfo.type,
            threatInfo.severity,
            options
          );

          sendThreatToDashboard(
            event,
            threatInfo.type,
            threatInfo.severity,
            true,
            threatInfo.description,
            options
          );

          if (isAuditEnabled) {
            logAuditEvent(event, 'blocked', `Threat blocked: ${threatInfo.type}`, 'critical');
          }

          return new Response(JSON.stringify({
            error: 'Request blocked by Silker AI',
            reason: 'Security threat detected',

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

    return originalFetch.call(this, input, init);
  };
}

