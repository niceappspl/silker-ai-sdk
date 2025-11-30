import http from 'http';
import httpProxy from 'http-proxy';
import { SilkerEvent, SilkerOptions } from '../types';
import { isAnomaly, setGlobalOptions } from '../detection';
import { sendAlertToDashboard, sendThreatToDashboard } from '../cloud/dashboard';
import { detectThreatType, setGlobalOptionsForThreat } from '../detection/threatDetection';
import { createLogger } from '../utils/logger';

/**
 * Uruchamia serwer proxy HTTP z monitorowaniem bezpieczeństwa Silker.
 * Wszystkie żądania przechodzące przez proxy są sprawdzane pod kątem anomalii.
 * @param options - Opcje konfiguracyjne Silker
 * @param targetUrl - URL docelowego serwera do przekierowania żądań
 * @param port - Port na którym ma działać serwer proxy (domyślnie: 8080)
 * @returns Serwer HTTP
 */
export function startProxyMode(options: SilkerOptions, targetUrl: string, port: number = 8080) {
  setGlobalOptions(options);
  const logger = createLogger(options);

  const proxy = httpProxy.createProxyServer({});

  const server = http.createServer(async (req, res) => {
    const event: SilkerEvent = {
      method: req.method || 'GET',
      url: req.url || '',
      ip: req.socket.remoteAddress,
      timestamp: Date.now(),
      userAgent: req.headers['user-agent'],
      headers: req.headers as Record<string, string>
    };

    const anomaly = isAnomaly(event);
    if (anomaly) {
      logger.debug('🚫 Proxy mode blocking request');

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

          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'Request blocked by Silker AI',
            reason: 'Security threat detected',

          }));
          return;
        }
      }

      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: 'Request blocked by Silker AI',
        reason: 'Security threat detected'
      }));
      return;
    }

    proxy.web(req, res, { target: targetUrl });
  });

  server.listen(port, () => {
    logger.info(`🌐 Silker proxy running on port ${port}, forwarding to ${targetUrl}`);
  });

  return server;
}

