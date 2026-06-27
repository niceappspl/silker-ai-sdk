/**
 * Silker self-host proxy (kontener).
 *
 * Lekki reverse proxy w Node, który reużywa ten sam silnik co SDK i Worker
 * (`@silker-ai/core`). Działa z DOWOLNYM backendem (PHP/Java/Python/Go/...) i
 * dowolnym hostingiem - bez Cloudflare, bez zmian w kodzie aplikacji.
 *
 * Ruch przechodzi przez kontener (na maszynie usera); decyzja block/allow zapada
 * lokalnie, do platformy leci tylko telemetria async - my pozostajemy poza ścieżką.
 */
import { createServer, IncomingMessage, ServerResponse } from 'http';
import {
  configureCore,
  inspectEvent,
  inspectResponseLeakage,
  buildThreatItem,
  buildRequestItem,
  sendEvents,
  EDGE_SAFE_FEATURES,
  MAX_RESPONSE_SCAN_BYTES,
  type SilkerEvent,
  type SilkerOptions,
  type TelemetryConfig,
} from '../../src/core';

const API_KEY = process.env.SILKER_API_KEY || '';
const APP_ID = process.env.SILKER_APP_ID;
const ENDPOINT = process.env.SILKER_ENDPOINT || 'https://platform.silkerai.com';
const TARGET = process.env.SILKER_TARGET || 'http://localhost:3000';
const PORT = Number(process.env.SILKER_PORT || 8080);

const MAX_BODY_BYTES = 10 * 1024 * 1024; // 10MB cap dla forwardu
const MAX_SCAN_BYTES = 50 * 1024; // 50KB do skanu
const HOP_BY_HOP = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'keep-alive']);

const telemetry: TelemetryConfig = { endpoint: ENDPOINT, apiKey: API_KEY, appId: APP_ID };

// Inspekcja odpowiedzi wychodzących włączona, chyba że jawnie wyłączona.
const RESPONSE_INSPECTION = EDGE_SAFE_FEATURES.responseInspection !== false;

const options: SilkerOptions = {
  apiKey: API_KEY,
  appId: APP_ID,
  features: {
    ...EDGE_SAFE_FEATURES,
    // Jedna instancja kontenera = stan w pamięci jest spójny (rate-limit/bany OK).
    ipBanning: true,
  },
};
configureCore(options);

function readRawBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      if (size < MAX_BODY_BYTES) {
        chunks.push(chunk);
        size += chunk.length;
      }
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', () => resolve(Buffer.concat(chunks)));
  });
}

function toHeaderRecord(req: IncomingMessage): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [key, value] of Object.entries(req.headers)) {
    headers[key] = Array.isArray(value) ? value.join(', ') : value ?? '';
  }
  return headers;
}

function buildEvent(req: IncomingMessage, headers: Record<string, string>, body: Buffer): SilkerEvent {
  const host = headers['host'] || 'localhost';
  const bodyText = body.length ? body.toString('utf8', 0, Math.min(body.length, MAX_SCAN_BYTES)) : '';

  // Query string jest częścią powierzchni ataku - skanujemy razem z body.
  let queryText = '';
  const qIndex = (req.url || '').indexOf('?');
  if (qIndex >= 0) {
    try {
      queryText = decodeURIComponent((req.url as string).slice(qIndex + 1));
    } catch {
      queryText = (req.url as string).slice(qIndex + 1);
    }
  }
  const combined = `${bodyText} ${queryText}`.trim();
  const scan = combined.length > 0 ? combined.slice(0, MAX_SCAN_BYTES) : undefined;

  const ip =
    headers['x-real-ip'] ||
    headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.socket.remoteAddress ||
    undefined;

  return {
    method: req.method || 'GET',
    url: `http://${host}${req.url || '/'}`,
    payload: scan,
    ip,
    timestamp: Date.now(),
    userAgent: headers['user-agent'],
    headers,
  };
}

async function forward(
  req: IncomingMessage,
  headers: Record<string, string>,
  body: Buffer,
): Promise<Response> {
  const targetUrl = new URL(req.url || '/', TARGET).toString();
  const forwardHeaders: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!HOP_BY_HOP.has(key.toLowerCase())) forwardHeaders[key] = value;
  }

  const method = req.method || 'GET';
  const hasBody = method !== 'GET' && method !== 'HEAD' && body.length > 0;

  return fetch(targetUrl, {
    method,
    headers: forwardHeaders,
    body: hasBody ? body : undefined,
    redirect: 'manual',
  });
}

async function relayResponse(upstream: Response, res: ServerResponse): Promise<void> {
  const headers: Record<string, string> = {};
  upstream.headers.forEach((value, key) => {
    if (!HOP_BY_HOP.has(key.toLowerCase())) headers[key] = value;
  });
  res.writeHead(upstream.status, headers);
  const buffer = Buffer.from(await upstream.arrayBuffer());
  res.end(buffer);
}

/**
 * Relay z inspekcją wycieku danych w odpowiedzi originu. Body jest buforowane
 * (proxy i tak je buforuje), skanowane pod kątem sekretów/PII i przekazywane
 * niezmienione. Wykrycie generuje zdarzenie "Data Leakage" (monitor - nie psujemy
 * odpowiedzi originu). Telemetria fire-and-forget.
 */
async function relayWithInspection(
  upstream: Response,
  res: ServerResponse,
  event: SilkerEvent,
  start: number,
): Promise<void> {
  const headers: Record<string, string> = {};
  upstream.headers.forEach((value, key) => {
    if (!HOP_BY_HOP.has(key.toLowerCase())) headers[key] = value;
  });
  const buffer = Buffer.from(await upstream.arrayBuffer());

  if (RESPONSE_INSPECTION && buffer.length > 0) {
    try {
      const text = buffer.toString('utf8', 0, Math.min(buffer.length, MAX_RESPONSE_SCAN_BYTES));
      const threat = inspectResponseLeakage(text, upstream.headers.get('content-type'));
      if (threat) {
        void sendEvents(telemetry, [buildThreatItem(event, threat, APP_ID, Date.now() - start)]);
      }
    } catch {
      // Inspekcja best-effort - nigdy nie blokuje przekazania odpowiedzi.
    }
  }

  res.writeHead(upstream.status, headers);
  res.end(buffer);
}

const HEALTH_PATH = '/_silker/health';

const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  const start = Date.now();
  let headers: Record<string, string> = {};
  let body: Buffer = Buffer.alloc(0);

  // Health probe served by the proxy itself (never forwarded to origin) -
  // used by Docker HEALTHCHECK / orchestrators.
  if ((req.url || '').split('?')[0] === HEALTH_PATH) {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', target: TARGET }));
    return;
  }

  try {
    headers = toHeaderRecord(req);
    body = await readRawBody(req);
    const event = buildEvent(req, headers, body);
    const result = inspectEvent(event);

    if (result.blocked && result.threat) {
      const item = buildThreatItem(event, result.threat, APP_ID, Date.now() - start);
      void sendEvents(telemetry, [item]);

      res.writeHead(403, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          error: 'Request blocked by Silker AI',
          reason: 'Security threat detected',
          type: result.threat.type,
        }),
      );
      return;
    }

    const upstream = await forward(req, headers, body);
    void sendEvents(telemetry, [buildRequestItem(event, upstream.status, Date.now() - start, APP_ID)]);
    await relayWithInspection(upstream, res, event, start);
  } catch {
    // Fail-open: spróbuj przekazać ruch; jeśli się nie da - 502.
    try {
      const upstream = await forward(req, headers, body);
      await relayResponse(upstream, res);
    } catch {
      if (!res.headersSent) res.writeHead(502, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'Bad gateway', reason: 'Origin unreachable' }));
    }
  }
});

server.listen(PORT, () => {
  console.log(`[Silker] proxy listening on :${PORT} → ${TARGET} (endpoint: ${ENDPOINT})`);
  if (!API_KEY) console.warn('[Silker] SILKER_API_KEY not set - telemetry disabled, detection still active.');
});
