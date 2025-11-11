import http from 'http';
import httpProxy from 'http-proxy';
import { VibeGuardEvent, VibeGuardOptions, CloudResponse } from '../types';
import { isAnomaly, setGlobalOptions } from '../detection';
import { sendToCloud } from '../cloud';

/**
 * Uruchamia serwer proxy HTTP z monitorowaniem bezpieczeństwa VibeGuard.
 * Wszystkie żądania przechodzące przez proxy są sprawdzane pod kątem anomalii.
 * @param options - Opcje konfiguracyjne VibeGuard
 * @param targetUrl - URL docelowego serwera do przekierowania żądań
 * @param port - Port na którym ma działać serwer proxy (domyślnie: 8080)
 * @returns Serwer HTTP
 */
export function startProxyMode(options: VibeGuardOptions, targetUrl: string, port: number = 8080) {
  setGlobalOptions(options);

  const proxy = httpProxy.createProxyServer({});

  const server = http.createServer(async (req, res) => {
    const event: VibeGuardEvent = {
      method: req.method || 'GET',
      url: req.url || '',
      ip: req.socket.remoteAddress,
      timestamp: Date.now(),
      userAgent: req.headers['user-agent'],
      headers: req.headers as Record<string, string>
    };

    const anomaly = isAnomaly(event);
    if (anomaly) {
      const cloudResponse = await sendToCloud(event, options);

      if (cloudResponse?.block) {
        if (options.debug) {
          console.log('🚫 Proxy mode blocking request');
        }

        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'Request blocked by VibeGuard',
          alertId: cloudResponse.alertId
        }));
        return;
      }
    }

    proxy.web(req, res, { target: targetUrl });
  });

  server.listen(port, () => {
    if (options.debug) {
      console.log(`🌐 VibeGuard proxy running on port ${port}, forwarding to ${targetUrl}`);
    }
  });

  return server;
}

