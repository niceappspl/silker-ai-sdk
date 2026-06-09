import { EventEmitter } from 'events';
import { SilkerEvent, SilkerOptions, DataLeakageConfig } from '../types';
import { isAnomaly, setGlobalOptions, banIp, isIpBanned, getDataLeakageConfig, redactJsonPayload } from '../detection';
import { detectThreatType, setGlobalOptionsForThreat } from '../detection/threatDetection';
import { recordPerformanceMetrics } from '../analytics/performance';
import { createLogger } from '../utils/logger';
import { sendRequestToDashboard, sendThreatToDashboard } from '../cloud/dashboard';
import { logAuditEvent } from '../monitoring/audit';
import { resolveSilkerOptions, warnMissingApiKeyOnce } from '../config/env';
import { applyProfile } from '../config/profiles';
import { runWithRequestContext } from '../utils/requestContext';

const vibeEmitter = new EventEmitter();
vibeEmitter.setMaxListeners(50);

/**
 * Tworzy middleware Express.js dla Silker.
 * Przechwytuje żądania Express, sprawdza je pod kątem anomalii i blokuje podejrzane żądania.
 * Konfiguracja jest opcjonalna — apiKey/appId/endpoint są czytane z env
 * (SILKER_API_KEY, SILKER_APP_ID, SILKER_ENDPOINT) jeśli nie podano ich jawnie.
 * @param inputOptions - Opcje konfiguracyjne Silker (opcjonalne)
 * @returns Middleware Express.js
 */
export function hookExpress(inputOptions: Partial<SilkerOptions> = {}) {
  const options = applyProfile(resolveSilkerOptions(inputOptions));
  setGlobalOptions(options);
  const logger = createLogger(options);

  const telemetryEnabled = options.features?.cloudCommunication !== false && !!options.apiKey;
  if (!options.apiKey) {
    warnMissingApiKeyOnce(logger);
  }

  logger.info('Silker middleware initialized');

  return async (req: any, res: any, next: any) => {
    try {
        // Skip scanning for static assets and technical endpoints
        const skipPatterns = [
          /favicon\.(ico|png|jpg|svg)$/i,
          /\.(css|js|map|woff|woff2|ttf|eot)$/i,
          /\/assets\//i,
          /\/static\//i,
          /\/public\//i,
          /_next\//i,
          /\.well-known\//i
        ];
        
        if (skipPatterns.some(pattern => pattern.test(req.originalUrl))) {
          return next();
        }
        
        // Limit payload size for analysis to avoid blocking event loop
        const MAX_ANALYSIS_SIZE = 10240; // 10KB

        const payloadParts: string[] = [];

        // Helper to safely add string content
        const addSafeContent = (obj: any) => {
            if (!obj) return;
            try {
                const str = JSON.stringify(obj);
                if (str.length > MAX_ANALYSIS_SIZE) {
                    payloadParts.push(str.substring(0, MAX_ANALYSIS_SIZE));
                } else {
                    payloadParts.push(str);
                }
            } catch (e) {
                // Ignore circular structure errors
            }
        };

        // Get real IP from proxy headers (Vercel, Cloudflare, etc.)
        const realIp = req.headers['x-real-ip'] || 
                       req.headers['x-forwarded-for']?.split(',')[0].trim() ||
                       req.ip || 
                       req.connection.remoteAddress;

        const start = Date.now();
        let redactionPerformed = false;
        let redactedFields: string[] = [];
        let dataTypesDetected: string[] = [];

        // Check if redaction mode is enabled and apply PII redaction
        const dataLeakageConfig = getDataLeakageConfig();
        if (dataLeakageConfig?.strategy === 'redact' && req.body) {
          const piiPatterns = typeof dataLeakageConfig === 'object' ? dataLeakageConfig.piiPatterns : undefined;
          const { redactedBody, result } = redactJsonPayload(req.body, piiPatterns);
          
          if (result.originalFlagged) {
            redactionPerformed = true;
            redactedFields = result.redactedFields;
            dataTypesDetected = result.dataTypesDetected;
            
            // Mutate req.body with redacted version
            req.body = redactedBody;
            
            // Update Content-Length header if present
            try {
              const newBodyString = JSON.stringify(redactedBody);
              const newContentLength = Buffer.byteLength(newBodyString, 'utf8');
              req.headers['content-length'] = String(newContentLength);
            } catch {
              // Ignore serialization errors
            }
          }
        }

        if (req.body) addSafeContent(req.body);
        if (req.query) addSafeContent(req.query);

        const event: SilkerEvent = {
          method: req.method,
          url: req.originalUrl,
          payload: payloadParts.join(' '),
          ip: realIp,
          timestamp: Date.now(),
          userAgent: req.get('User-Agent'),
          headers: req.headers as Record<string, string>,
          complianceTags: redactionPerformed ? ['GDPR', 'GDPR_ART_32'] : undefined,
          dataTypesDetected: dataTypesDetected.length > 0 ? dataTypesDetected : undefined,
        };

        // Log redaction event if PII was redacted
        if (redactionPerformed && options.features?.auditLogging !== false) {
          logAuditEvent(event, 'redacted', 'PII redacted from request', 'medium', {
            originalFlagged: true,
            actionTaken: 'redacted',
            redactedFields,
            complianceTags: ['GDPR_ART_32'],
          });
        }

        res.on('finish', () => {
          try {
              // Skip if this request was already reported as a threat
              if ((req as any)._silkerThreatReported) return;

              const duration = Date.now() - start;
              
              // Record performance metrics locally for health checks
              recordPerformanceMetrics(event, duration, res.statusCode);

              if (telemetryEnabled) {
                sendRequestToDashboard(event, res.statusCode, duration, options);
              }
          } catch (err) {
              logger.error('[Silker SDK] Error in response finish handler:', err);
              // Don't crash - just log
          }
        });

        // 1. First, check if there's a specific security threat in this request
        let anomaly = false;
        try {
          anomaly = isAnomaly(event);
        } catch (error) {
          logger.error('[Silker SDK] Error detecting anomaly, allowing request:', error);
          anomaly = false; // Fail open
        }

        if (anomaly) {
          try {
            // Automatically ban IP for a while after detecting an anomaly if feature is enabled
            if (event.ip && options.features?.ipBanning !== false) {
              banIp(event.ip);
            }

            // Record metrics locally for blocked request
            recordPerformanceMetrics(event, Date.now() - start, 403);
            
            // Mark as reported to prevent duplicate in finish handler
            (req as any)._silkerThreatReported = true;

            // Send threat to dashboard with timeout
            if (telemetryEnabled) {
              setGlobalOptionsForThreat(options);

              const threatInfo = detectThreatType(event);
              if (threatInfo) {
                const duration = Date.now() - start;
                // Fire-and-forget: never block the response on telemetry delivery.
                sendThreatToDashboard(
                  event,
                  threatInfo.type,
                  threatInfo.severity as 'critical' | 'high' | 'medium' | 'low',
                  true, // blocked
                  threatInfo.description,
                  options,
                  duration
                );

                return res.status(403).json({
                  error: 'Request blocked by Silker AI',
                  reason: 'Security threat detected',
                  type: threatInfo.type
                });
              }
            }

            // Block even if cloud communication is disabled
            return res.status(403).json({
              error: 'Request blocked by Silker AI',
              reason: 'Security threat detected'
            });
          } catch (error) {
            // If blocking fails, log and allow request (fail open)
            logger.error('[Silker SDK] Error blocking request, allowing through:', error);
          }
        }

        // 2. If no specific anomaly, check if IP is already banned to block early
        if (event.ip && options.features?.ipBanning !== false && isIpBanned(event.ip)) {
          // Mark as reported to prevent duplicate in finish handler
          (req as any)._silkerThreatReported = true;

          // Report as threat even if already banned, so dashboard shows activity
          if (telemetryEnabled) {
            // Fire-and-forget: never block the response on telemetry delivery.
            sendThreatToDashboard(
              event,
              'Banned IP Activity',
              'medium',
              true,
              'Request from a temporarily banned IP address',
              options,
              Date.now() - start
            );
          }

          return res.status(403).json({
            error: 'Request blocked by Silker AI',
            reason: 'IP address is temporarily banned'
          });
        }

        // Run the downstream chain inside the request context so the fetch hook
        // can read the client IP without relying on global mutable state.
        return runWithRequestContext({ ip: realIp }, () => next());
    } catch (error) {
        logger.error('Silker middleware error:', error);
        // Always fail open to protect user application unless explicitly configured otherwise
        // If user wants strict mode, they should have a way, but MVP goal is "never crash"
        next();
    }
  };
}

/**
 * Zwraca emiter zdarzeń Silker.
 * @returns Emiter zdarzeń EventEmitter
 */
export function getVibeEmitter(): EventEmitter {
  return vibeEmitter;
}
