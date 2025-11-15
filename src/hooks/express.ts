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

    const event: VibeGuardEvent = {
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

      const cloudResponse = options.features?.cloudCommunication !== false 
        ? await sendToCloud(event, options)
        : null;

      return res.status(403).json({
        error: 'Request blocked by Silker AI',
        reason: 'Security threat detected',
        alertId: cloudResponse?.alertId
      });
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

