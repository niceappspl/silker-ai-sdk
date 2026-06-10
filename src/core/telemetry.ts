/**
 * Edge-safe telemetria dla powłok core (Worker, kontener).
 * Używa standardowego `fetch` (Worker, Node 18+). Bez axios / Node API.
 * Format zgodny z SDK i z `/api/ingest` platformy: { events: [{ type, endpoint, payload, timestamp }] }.
 */
import { SilkerEvent } from '../types';
import { ThreatInfo } from '../detection/threatDetection';
import { SDK_VERSION } from '../version';

export interface TelemetryConfig {
  /** Bazowy URL platformy, np. https://silkerai.com */
  endpoint: string;
  /** Klucz API aplikacji (sk_...). */
  apiKey: string;
  /** Identyfikator aplikacji w platformie. */
  appId?: string;
}

interface TelemetryItem {
  type: 'threat' | 'request';
  endpoint: string;
  payload: Record<string, unknown>;
  timestamp: number;
}

function normalizeBaseUrl(endpoint: string): string {
  let base = endpoint || 'https://platform.silkerai.com';
  if (base.includes('/api')) {
    base = base.replace('/api', '');
  }
  return base.replace(/\/$/, '');
}

/** Buduje event zagrożenia w formacie ingest. */
export function buildThreatItem(
  event: SilkerEvent,
  threat: ThreatInfo,
  appId: string | undefined,
  responseTime?: number,
): TelemetryItem {
  const query = event.url.split('?')[1] || '';
  return {
    type: 'threat',
    endpoint: '/api/threats',
    timestamp: Date.now(),
    payload: {
      type: threat.type,
      severity: threat.severity,
      blocked: true,
      description: threat.description,
      ip: event.ip || 'unknown',
      endpoint: event.url || '/',
      method: event.method || 'UNKNOWN',
      headers: event.headers || {},
      body: typeof event.payload === 'string' ? event.payload : '',
      query,
      user_agent: event.userAgent || 'unknown',
      app_id: appId,
      response_time: responseTime,
      ip__banning_enabled: false,
    },
  };
}

/** Buduje event zwykłego requestu w formacie ingest. */
export function buildRequestItem(
  event: SilkerEvent,
  statusCode: number,
  responseTime: number,
  appId: string | undefined,
): TelemetryItem {
  return {
    type: 'request',
    endpoint: '/api/requests',
    timestamp: Date.now(),
    payload: {
      endpoint: event.url || '/',
      method: event.method || 'GET',
      status_code: statusCode,
      response_time: responseTime,
      ip: event.ip || 'unknown',
      user_agent: event.userAgent || 'unknown',
      app_id: appId,
    },
  };
}

/** Dane zwracane przez `/api/ingest` (konfiguracja zdalna + bany). */
export interface IngestResponseData {
  bannedIps?: { ip: string; until: string }[];
  config?: { features?: Record<string, unknown> };
}

/**
 * Wysyła batch eventów do `/api/ingest`. Fire-and-forget po stronie wywołującego
 * (w Workerze opakuj w `ctx.waitUntil`). Nigdy nie rzuca.
 * Zwraca dane z odpowiedzi ingestu (remote config / bany) lub null -
 * powłoka może je zaaplikować (np. `applyRemoteFeatures` / `syncBans`).
 */
export async function sendEvents(config: TelemetryConfig, events: TelemetryItem[]): Promise<IngestResponseData | null> {
  if (!config.apiKey || events.length === 0) return null;
  const ingestUrl = `${normalizeBaseUrl(config.endpoint)}/api/ingest`;
  try {
    const response = await fetch(ingestUrl, {
      method: 'POST',
      headers: {
        'x-api-key': config.apiKey,
        'content-type': 'application/json',
        'x-silker-client-version': SDK_VERSION,
      },
      body: JSON.stringify({ events }),
    });
    const json = (await response.json().catch(() => null)) as { data?: IngestResponseData } | null;
    return json?.data ?? null;
  } catch {
    // Telemetria jest best-effort - nie wpływa na ruch usera.
    return null;
  }
}
