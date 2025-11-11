import { VibeGuardEvent, VibeGuardOptions, CloudResponse } from '../types';
import { isAnomaly, setGlobalOptions } from '../detection';
import { sendToCloud } from '../cloud';
import { logAuditEvent } from '../monitoring/audit';

let globalOptions: VibeGuardOptions | null = null;

/**
 * Przechwytuje globalną funkcję fetch i dodaje monitorowanie bezpieczeństwa.
 * Wszystkie wywołania fetch są sprawdzane pod kątem anomalii przed wykonaniem.
 * @param options - Opcje konfiguracyjne VibeGuard
 */
export function hookFetch(options: VibeGuardOptions) {
  globalOptions = options;
  setGlobalOptions(options);

  const originalFetch = global.fetch;

  global.fetch = async function(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const method = init?.method || 'GET';

    const ip = (global as any).request?.ip || (global as any).req?.connection?.remoteAddress;

    const event: VibeGuardEvent = {
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
        console.log('🚨 Anomaly detected, consulting cloud...');
      }

      const isAuditEnabled = options.features?.auditLogging !== false;
      if (isAuditEnabled) {
        logAuditEvent(event, 'flagged', 'Security anomaly detected', 'high');
      }

      const cloudResponse = options.features?.cloudCommunication !== false 
        ? await sendToCloud(event, options)
        : null;

      if (cloudResponse?.block) {
        if (options.debug) {
          console.log('🚫 Cloud says BLOCK! Returning 403');
        }

        if (isAuditEnabled) {
          logAuditEvent(event, 'blocked', `Cloud blocked: ${cloudResponse.fixSnippet || 'Unknown threat'}`, 'critical');
        }

        return new Response(JSON.stringify({
          error: 'Request blocked by VibeGuard',
          alertId: cloudResponse.alertId
        }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      if (isAuditEnabled) {
        logAuditEvent(event, 'allowed', 'Anomaly flagged but allowed by cloud', 'medium');
      }
    } else {
      if (options.features?.auditLogging !== false) {
        logAuditEvent(event, 'allowed', 'Request passed security checks', 'low');
      }
    }

    return originalFetch.call(this, input, init);
  };
}

