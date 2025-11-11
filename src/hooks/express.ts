import { EventEmitter } from 'events';
import { VibeGuardEvent, VibeGuardOptions, CloudResponse } from '../types';
import { isAnomaly, setGlobalOptions } from '../detection';
import { sendToCloud } from '../cloud';

const vibeEmitter = new EventEmitter();

/**
 * Tworzy middleware Express.js dla VibeGuard.
 * Przechwytuje żądania Express, sprawdza je pod kątem anomalii i blokuje podejrzane żądania.
 * @param options - Opcje konfiguracyjne VibeGuard
 * @returns Middleware Express.js
 */
export function hookExpress(options: VibeGuardOptions) {
  setGlobalOptions(options);

  return async (req: any, res: any, next: any) => {
    const event: VibeGuardEvent = {
      method: req.method,
      url: req.originalUrl,
      payload: JSON.stringify(req.body || {}),
      ip: req.ip || req.connection.remoteAddress,
      timestamp: Date.now(),
      userAgent: req.get('User-Agent'),
      headers: req.headers as Record<string, string>
    };

    (global as any).request = req;

    vibeEmitter.emit('request', event);

    const anomaly = isAnomaly(event);
    if (anomaly) {
      const cloudResponse = options.features?.cloudCommunication !== false 
        ? await sendToCloud(event, options)
        : null;

      if (cloudResponse?.block) {
        if (options.debug) {
          console.log('🚫 Express middleware blocking request');
        }

        return res.status(403).json({
          error: 'Request blocked by VibeGuard',
          alertId: cloudResponse.alertId
        });
      }
    }

    next();
  };
}

/**
 * Zwraca emiter zdarzeń VibeGuard.
 * @returns Emiter zdarzeń EventEmitter
 */
export function getVibeEmitter(): EventEmitter {
  return vibeEmitter;
}

