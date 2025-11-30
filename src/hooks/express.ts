import { EventEmitter } from 'events';
import { SilkerEvent, SilkerOptions } from '../types';
import { isAnomaly, setGlobalOptions } from '../detection';
import { detectThreatType, setGlobalOptionsForThreat } from '../detection/threatDetection';
import { sendThreatToDashboard } from '../cloud/dashboard';

const vibeEmitter = new EventEmitter();

/**
 * Tworzy middleware Express.js dla Silker.
 * Przechwytuje żądania Express, sprawdza je pod kątem anomalii i blokuje podejrzane żądania.
 * @param options - Opcje konfiguracyjne Silker
 * @returns Middleware Express.js
 */
export function hookExpress(options: SilkerOptions) {
  setGlobalOptions(options);

  console.log('🛡️ Silker middleware initialized with dashboardUrl:', options.dashboardUrl);

  return async (req: any, res: any, next: any) => {
    console.log('🔍 Silker middleware processing request:', req.method, req.originalUrl);
    const allData: any = {
      ...req.body,
      ...req.query,
      ...req.params
    };

    const payloadParts: string[] = [];

    if (req.body && Object.keys(req.body).length > 0) {
      Object.values(req.body).forEach(value => {
        if (typeof value === 'string') {
          payloadParts.push(value);
        }
      });
      payloadParts.push(JSON.stringify(req.body));
    }

    if (req.query && Object.keys(req.query).length > 0) {
      Object.values(req.query).forEach(value => {
        if (typeof value === 'string') {
          payloadParts.push(value);
        }
      });
      payloadParts.push(JSON.stringify(req.query));
    }

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

    vibeEmitter.emit('request', event);

    const anomaly = isAnomaly(event);
    if (anomaly) {
      if (options.debug) {
        console.log('🚫 Anomaly detected, blocking request:', req.method, req.originalUrl);
      }

      if (options.features?.cloudCommunication !== false && options.dashboardUrl) {
        setGlobalOptionsForThreat(options);

        const threatInfo = detectThreatType(event);
        if (threatInfo) {
          // Send alert to dashboard using new sync mechanism
          // Send alert to dashboard using unified telemetry
          sendThreatToDashboard(
            event,
            threatInfo.type,
            threatInfo.severity as 'critical' | 'high' | 'medium' | 'low',
            true, // blocked
            threatInfo.description,
            options
          );

          if (options.debug) {
            console.log('📤 Alert sent to dashboard:', threatInfo.type);
          }

          return res.status(403).json({
            error: 'Request blocked by Silker AI',
            reason: 'Security threat detected',
            type: threatInfo.type
          });
        }
      }

      return res.status(403).json({
        error: 'Request blocked by Silker AI',
        reason: 'Security threat detected'
      });
    }

    next();
  };
}

/**
 * Zwraca emiter zdarzeń Silker.
 * @returns Emiter zdarzeń EventEmitter
 */
export function getVibeEmitter(): EventEmitter {
  return vibeEmitter;
}

