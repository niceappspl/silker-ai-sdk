import { SilkerOptions } from '../types';
import { syncBans } from '../detection/rateLimit';
import { applyRemoteFeatures } from '../detection/anomaly';
import { SDK_VERSION } from '../version';
import { createLogger } from '../utils/logger';

/**
 * Pull-sync: aktywne pobranie listy zbanowanych IP i configu z platformy.
 *
 * Telemetria dostarcza bany tylko reaktywnie (w odpowiedzi ingest, po flushu),
 * wiec swiezy proces - zwlaszcza serverless (Vercel/Lambda), gdzie kazdy isolate
 * startuje z pustym banMap - nie egzekwuje banow do pierwszego round-tripu.
 * Ten modul pobiera bany/config aktywnie (na starcie i z TTL), w tle, bez
 * dodawania latencji w sciezce zadania. Wspoldzielony stan miedzy instancjami
 * (twarde egzekwowanie per-request) nadal wymaga `SilkerStateStore` (Redis/KV).
 */

let lastSyncAt = 0;
let inFlight: Promise<void> | null = null;
const SYNC_TTL_MS = 30_000;

function resolveBaseUrl(options: SilkerOptions): string {
  const isDev = process.env.NODE_ENV === 'development' || process.env.SILKER_DEV === 'true';
  let baseUrl = options.endpoint || (isDev ? 'http://localhost:3000' : 'https://platform.silkerai.com');
  if (baseUrl.includes('/api')) {
    baseUrl = baseUrl.replace('/api', '');
  }
  return baseUrl.replace(/\/$/, '');
}

async function doSync(options: SilkerOptions): Promise<void> {
  const logger = createLogger(options);
  try {
    const base = resolveBaseUrl(options);
    const url = `${base}/api/sdk/sync${options.appId ? `?appId=${encodeURIComponent(options.appId)}` : ''}`;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);

    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'x-api-key': options.apiKey || '',
        'x-silker-client-version': SDK_VERSION,
      },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!res.ok) return;

    const json = (await res.json()) as {
      data?: {
        bannedIps?: { ip: string; until: string }[];
        config?: { features?: Record<string, unknown> };
      };
    };
    const data = json?.data;
    if (!data) return;

    if (Array.isArray(data.bannedIps)) {
      syncBans(data.bannedIps);
    }
    if (options.remoteConfig !== false && data.config?.features) {
      applyRemoteFeatures(data.config.features);
    }
  } catch (error) {
    logger.debug?.('[Silker SDK] Ban/config pull-sync failed:', error);
  }
}

/**
 * Wyzwala pull-sync banow/configu w tle, jesli minal TTL (lub `force`).
 * Nigdy nie blokuje wywolujacego (fire-and-forget). No-op bez apiKey.
 */
export function maybePrimeBansAndConfig(options: SilkerOptions, force = false): void {
  if (!options.apiKey) return;

  const now = Date.now();
  if (!force && now - lastSyncAt < SYNC_TTL_MS) return;
  if (inFlight) return;

  lastSyncAt = now;
  inFlight = doSync(options).finally(() => {
    inFlight = null;
  });
}

/** Reset stanu cache (dla testow). */
export function resetSyncStateForTests(): void {
  lastSyncAt = 0;
  inFlight = null;
}
