/**
 * @silker-ai/core - edge-safe silnik detekcji.
 *
 * Współdzielony rdzeń używany przez wszystkie powłoki dostarczania:
 * SDK (Node/Express/fetch), Cloudflare Worker oraz kontener self-host.
 * Nie zawiera zależności Node-only (brak `Buffer`, `axios`, `process`),
 * dzięki czemu działa na runtime V8 (edge) i w Node.
 *
 * Powłoka odpowiada za: transport (telemetria), stan rozproszony (KV/DO)
 * i forward ruchu. Core odpowiada wyłącznie za decyzję block/allow.
 */
import {
  isAnomaly,
  setGlobalOptions as setDetectionOptions,
  inspectResponseText,
  isScannableContentType,
  guardStreamingResponse,
  isStreamingContentType,
} from '../detection';
import { setGlobalOptions as setBehaviorOptions } from '../analytics/userBehavior';
import {
  detectThreatType,
  setGlobalOptionsForThreat,
  ThreatInfo,
} from '../detection/threatDetection';
import { SilkerOptions, SilkerEvent, SilkerFeatures } from '../types';
import { DEFAULT_SCAN_LIMIT_BYTES } from '../detection/features';

/**
 * Maksymalny rozmiar body skanowanego pod kątem zagrożeń (ochrona przed DoS/latencją).
 * Współdzielony limit ze wszystkimi powłokami (express hook, isAnomaly) - 100KB.
 */
export const MAX_BODY_SCAN_BYTES = DEFAULT_SCAN_LIMIT_BYTES;

/**
 * Domyślny zestaw funkcji dla powłok edge/proxy (Worker, kontener).
 *
 * Włączone: SQLi, XSS, path traversal, prompt injection, data leakage, rate limit,
 * file upload, threat intelligence - wysokowartościowe, niskie false-positive na surowym ruchu HTTP.
 *
 * Wyłączone: detektory zależne od kontekstu aplikacji (SSRF/CSRF/IDOR/host header,
 * zero-trust, access control, compliance, third-party, schema) - na warstwie sieci
 * generują false-positives na normalnym ruchu (brak Origin/auth itd.).
 */
export const EDGE_SAFE_FEATURES: SilkerFeatures = {
  disableLegacySecurity: true,
  zeroTrustDetection: false,
  accessControlDetection: false,
  complianceDetection: false,
  thirdPartyDetection: false,
  apiSchemaValidation: false,
};

/**
 * Konfiguruje silnik detekcji. Wywołać raz przed pierwszym `inspectEvent`.
 */
export function configureCore(options: SilkerOptions): void {
  setDetectionOptions(options);
  setBehaviorOptions(options);
  setGlobalOptionsForThreat(options);
}

/** Wynik inspekcji pojedynczego zdarzenia. */
export interface InspectResult {
  /** Czy żądanie powinno zostać zablokowane. */
  blocked: boolean;
  /** Szczegóły zagrożenia (typ, severity, opis) jeśli zablokowano. */
  threat: ThreatInfo | null;
}

/**
 * Inspekcja zdarzenia: zwraca decyzję block/allow + typ zagrożenia.
 * Czysto synchroniczna, lekka (regex/heurystyki) - bezpieczna w ścieżce żądania.
 */
export function inspectEvent(event: SilkerEvent): InspectResult {
  if (isAnomaly(event)) {
    return { blocked: true, threat: detectThreatType(event) };
  }
  return { blocked: false, threat: null };
}

/**
 * Buduje `SilkerEvent` ze standardowego Web `Request` (Worker, Node 18+, edge).
 * Body czytane jest z klona (oryginał pozostaje do forwardu) i przycinane do limitu.
 * @param maxBytes - Opcjonalny limit skanu (domyślnie MAX_BODY_SCAN_BYTES; powłoka
 *   może przekazać `options.maxPayloadSize` użytkownika)
 */
export async function eventFromRequest(request: Request, ip?: string, maxBytes: number = MAX_BODY_SCAN_BYTES): Promise<SilkerEvent> {
  const headers: Record<string, string> = {};
  request.headers.forEach((value, key) => {
    headers[key] = value;
  });

  const method = request.method || 'GET';
  let bodyText = '';

  if (method !== 'GET' && method !== 'HEAD') {
    try {
      const text = await request.clone().text();
      bodyText = text.length > maxBytes ? text.slice(0, maxBytes) : text;
    } catch {
      // Brak/niereadable body - pomijamy skan body.
    }
  }

  // Query string jest częścią powierzchni ataku (SQLi/XSS w parametrach) - skanujemy razem z body.
  let queryText = '';
  try {
    queryText = decodeURIComponent(new URL(request.url).search.replace(/^\?/, ''));
  } catch {
    // Niepoprawny URL/encoding - pomijamy query.
  }

  const combined = `${bodyText} ${queryText}`.trim();
  const payload = combined.length > 0 ? combined.slice(0, maxBytes) : undefined;

  const resolvedIp =
    ip ||
    headers['x-real-ip'] ||
    headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    headers['cf-connecting-ip'];

  return {
    method,
    url: request.url,
    payload,
    ip: resolvedIp,
    timestamp: Date.now(),
    userAgent: headers['user-agent'],
    headers,
  };
}

/**
 * Limit treści odpowiedzi skanowanej pod kątem wycieku danych (Worker/kontener).
 */
export const MAX_RESPONSE_SCAN_BYTES = 256 * 1024;

/**
 * Inspekcja odpowiedzi originu pod kątem wycieku danych. Zwraca ThreatInfo
 * (typ "Data Leakage") gdy wykryto sekrety/PII, w przeciwnym razie null.
 * Edge-safe; pomija odpowiedzi binarne (po Content-Type).
 */
export function inspectResponseLeakage(text: string, contentType?: string | null): ThreatInfo | null {
  if (!isScannableContentType(contentType)) return null;
  const result = inspectResponseText(text, MAX_RESPONSE_SCAN_BYTES);
  if (!result.leaked) return null;
  return {
    type: 'Data Leakage',
    severity: 'critical',
    description: `Sensitive data leak in outbound response: ${result.findings.join(', ')}`,
  };
}

export { isAnomaly, detectThreatType };
export { inspectResponseText, isScannableContentType, guardStreamingResponse, isStreamingContentType };
export type { SilkerFeatures };
export {
  buildThreatItem,
  buildRequestItem,
  sendEvents,
  type TelemetryConfig,
  type IngestResponseData,
} from './telemetry';
export type { SilkerOptions, SilkerEvent, ThreatInfo };
