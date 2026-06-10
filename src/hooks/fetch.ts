import { SilkerEvent, SilkerOptions } from '../types';
import { isAnomaly, setGlobalOptions, getDataLeakageConfig, redactPii, detectSsrfAttack } from '../detection';
import { sendThreatToDashboard, sendRequestToDashboard } from '../cloud/dashboard';
import { detectThreatType, setGlobalOptionsForThreat } from '../detection/threatDetection';
import { logAuditEvent } from '../monitoring/audit';
import { createLogger } from '../utils/logger';
import { recordPerformanceMetrics } from '../analytics/performance';
import { resolveSilkerOptions, warnMissingApiKeyOnce } from '../config/env';
import { getRequestContext } from '../utils/requestContext';
import { isFeatureEnabled } from '../detection/features';

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
 * Domyślnie działa w trybie monitor-only (telemetria bez blokowania) -
 * blokowanie wychodzących żądań wymaga ustawienia `blockOutgoing: true`.
 * @param inputOptions - Opcje konfiguracyjne Silker (opcjonalne, env fallback)
 */
export function hookFetch(inputOptions: Partial<SilkerOptions> = {}) {
  const options = resolveSilkerOptions(inputOptions);
  try {
    if (originalFetchBackup !== null) {
      return;
    }

    globalOptions = options;
    setGlobalOptions(options);
    const logger = createLogger(options);

    const telemetryEnabled = options.features?.cloudCommunication !== false && !!options.apiKey;
    if (!options.apiKey) {
      warnMissingApiKeyOnce(logger);
    }

    originalFetchBackup = global.fetch;

    global.fetch = async function (input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const start = Date.now();
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const method = init?.method || 'GET';

    const ip = getRequestContext()?.ip;

    let modifiedInit = init;
    let redactionPerformed = false;
    let redactedFields: string[] = [];
    let dataTypesDetected: string[] = [];

    // Check if redaction mode is enabled and apply PII redaction
    const dataLeakageConfig = getDataLeakageConfig();
    if (dataLeakageConfig?.strategy === 'redact' && init?.body) {
      const bodyString = typeof init.body === 'string' ? init.body : safeStringify(init.body);
      const piiPatterns = typeof dataLeakageConfig === 'object' ? dataLeakageConfig.piiPatterns : undefined;
      const result = redactPii(bodyString, piiPatterns);
      
      if (result.originalFlagged) {
        redactionPerformed = true;
        redactedFields = result.redactedFields;
        dataTypesDetected = result.dataTypesDetected;
        
        // Create modified init with redacted body
        modifiedInit = {
          ...init,
          body: result.redactedPayload,
          headers: {
            ...(init.headers as Record<string, string>),
            'content-length': String(Buffer.byteLength(result.redactedPayload, 'utf8')),
          },
        };
      }
    }

    const event: SilkerEvent = {
      method,
      url,
      payload: modifiedInit?.body
        ? (typeof modifiedInit.body === 'string' ? modifiedInit.body : safeStringify(modifiedInit.body))
        : undefined,
      ip,
      timestamp: start,
      userAgent: (modifiedInit?.headers as any)?.['User-Agent'],
      headers: modifiedInit?.headers as Record<string, string>,
      complianceTags: redactionPerformed ? ['GDPR', 'GDPR_ART_32'] : undefined,
      dataTypesDetected: dataTypesDetected.length > 0 ? dataTypesDetected : undefined,
    };

    // Log redaction event if PII was redacted
    if (redactionPerformed && options.features?.auditLogging !== false) {
      logAuditEvent(event, 'redacted', 'PII redacted from outgoing request', 'medium', {
        originalFlagged: true,
        actionTaken: 'redacted',
        redactedFields,
        complianceTags: ['GDPR_ART_32'],
      });
    }

    // SSRF for OUTGOING requests is the primary purpose of this hook, so it is
    // governed by the dedicated `outboundSsrfProtection` feature (default TRUE in
    // DEFAULT_FEATURES) - separate from incoming `ssrfDetection` (default false).
    // Backward compat: an explicit `ssrfDetection: false` also disables outbound.
    const outboundSsrfEnabled =
      options.features?.ssrfDetection === false
        ? false
        : isFeatureEnabled(options, 'outboundSsrfProtection');
    const ssrfDetected = outboundSsrfEnabled && detectSsrfAttack(event);
    const anomaly = isAnomaly(event) || ssrfDetected;

    if (anomaly) {
      // Monitor-only by default: report telemetry but do not block,
      // unless `blockOutgoing: true` is explicitly set.
      const shouldBlock = options.blockOutgoing === true;
      logger.debug(shouldBlock ? 'Anomaly detected, blocking request' : 'Anomaly detected (monitor-only)');

      const isAuditEnabled = options.features?.auditLogging !== false;
      if (isAuditEnabled) {
        logAuditEvent(event, 'flagged', 'Security anomaly detected', 'high');
      }

      let threatType: string | undefined;
      if (telemetryEnabled) {
        setGlobalOptionsForThreat(options);
        // Outbound SSRF jest wykrywany lokalnie (osobny feature flag), więc
        // klasyfikujemy go wprost - detectThreatType gateuje SSRF na incoming fladze.
        const threatInfo = ssrfDetected
          ? {
              type: 'SSRF',
              severity: 'critical' as const,
              description: `Server-side request forgery attempt detected in ${url}`,
            }
          : detectThreatType(event);
        if (threatInfo) {
          threatType = threatInfo.type;
          // Fire-and-forget: never block the request path on telemetry delivery.
          sendThreatToDashboard(
            event,
            threatInfo.type,
            threatInfo.severity,
            shouldBlock,
            threatInfo.description,
            options,
            Date.now() - start
          );
        }
      }

      if (shouldBlock) {
        if (isAuditEnabled) {
          logAuditEvent(event, 'blocked', threatType ? `Threat blocked: ${threatType}` : 'Security anomaly detected', 'critical');
        }

        return new Response(JSON.stringify({
          error: 'Request blocked by Silker AI',
          reason: 'Security threat detected',
          ...(threatType ? { type: threatType } : {})
        }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    } else {
      if (options.features?.auditLogging !== false) {
        logAuditEvent(event, 'allowed', 'Request passed security checks', 'low');
      }
    }

    try {
        const response = await originalFetchBackup!.call(this, input, modifiedInit);
        const duration = Date.now() - start;
        
        // Record performance metrics
        recordPerformanceMetrics(event, duration, response.status);

        // Send request metrics to dashboard if enabled (fire-and-forget, never blocks)
        if (telemetryEnabled) {
            sendRequestToDashboard(event, response.status, duration, options);
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

