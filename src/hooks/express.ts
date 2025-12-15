import { EventEmitter } from 'events';
import { SilkerEvent, SilkerOptions } from '../types';
import { isAnomaly, setGlobalOptions } from '../detection';
import { detectThreatType, setGlobalOptionsForThreat } from '../detection/threatDetection';
import { getPerformanceReport, recordPerformanceMetrics } from '../analytics/performance';
import { getAuditLogs, getAuditSummary, logAuditEvent } from '../monitoring/audit';
import { getRuntimeConfig, updateRuntimeConfig } from '../config';
import { performHealthCheck } from '../monitoring/health';
import { performApiValidation } from '../validation/apiSchema';
import { validateSecurityHeaders } from '../validation/securityHeaders';
import { analyzeUserBehavior } from '../analytics/userBehavior';
import { createLogger } from '../utils/logger';
import { sendRequestToDashboard, sendThreatToDashboard } from '../cloud/dashboard';

const vibeEmitter = new EventEmitter();
let isListenerRegistered = false;

/**
 * Tworzy middleware Express.js dla Silker.
 * Przechwytuje żądania Express, sprawdza je pod kątem anomalii i blokuje podejrzane żądania.
 * @param options - Opcje konfiguracyjne Silker
 * @returns Middleware Express.js
 */
export function hookExpress(options: SilkerOptions) {
  setGlobalOptions(options);
  const logger = createLogger(options);

  if (!isListenerRegistered) {
    // Listener usunięty stąd, bo wysyłamy teraz w res.on('finish')
    // vibeEmitter.on('request', ...) - logic moved to finish handler
    isListenerRegistered = true;
  }

  logger.info('🛡️ Silker middleware initialized');

  return async (req: any, res: any, next: any) => {
    try {
        logger.debug('🔍 Silker middleware processing request:', req.method, req.originalUrl);
        
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

        if (req.body) addSafeContent(req.body);
        if (req.query) addSafeContent(req.query);

        const event: SilkerEvent = {
          method: req.method,
          url: req.originalUrl,
          payload: payloadParts.join(' '),
          ip: req.ip || req.connection.remoteAddress,
          timestamp: Date.now(),
          userAgent: req.get('User-Agent'),
          headers: req.headers as Record<string, string>
        };

        (global as any).request = req;

        // Przechwytywanie zakończenia requestu dla pomiaru czasu i statusu
        const start = Date.now();
        
        res.on('finish', () => {
          try {
              const duration = Date.now() - start;
              // Aktualizujemy event o rzeczywiste dane
              // const completedEvent = { ...event, statusCode: res.statusCode, duration }; // unused
              
              // Record performance metrics locally for health checks
              recordPerformanceMetrics(event, duration, res.statusCode);

              if (options.features?.cloudCommunication !== false && options.appId) {
                sendRequestToDashboard(event, res.statusCode, duration, options);
              }
          } catch (err) {
              logger.error('Error in response finish handler:', err);
          }
        });

        const anomaly = isAnomaly(event);
        if (anomaly) {
          logger.debug('🚫 Anomaly detected, blocking request:', req.method, req.originalUrl);

          // Send alert to dashboard in background (fire-and-forget)
          // This MUST NOT block the response
          if (options.features?.cloudCommunication !== false && options.appId) {
            setGlobalOptionsForThreat(options);

            const threatInfo = detectThreatType(event);
            if (threatInfo) {
              // Fire-and-forget: send to dashboard without waiting
              sendThreatToDashboard(
                event,
                threatInfo.type,
                threatInfo.severity as 'critical' | 'high' | 'medium' | 'low',
                true, // blocked
                threatInfo.description,
                options
              ).catch(err => {
                logger.debug('⚠️ Failed to send threat to dashboard (non-blocking):', err.message);
              });

              // Block immediately, don't wait for dashboard
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
        }

        next();
    } catch (error) {
        logger.error('🚨 Silker middleware error:', error);
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
