/**
 * Silker Cloudflare Worker (MVP).
 *
 * Inspekcja request → block (403) / forward do originu, telemetria async do platformy.
 * Reużywa ten sam silnik co SDK (`@silker-ai/core`) - zero duplikacji detekcji.
 *
 * Wdrożenie:
 *   wrangler secret put SILKER_API_KEY
 *   ustaw SILKER_APP_ID i SILKER_TARGET (origin) w wrangler.toml
 *   wrangler deploy
 *
 * Uwaga MVP: rate-limit/bany działają per-isolate (każdy edge osobno).
 * Globalny stan (KV/Durable Objects) to etap parytetu z SDK.
 */
import {
  configureCore,
  eventFromRequest,
  inspectEvent,
  inspectResponseLeakage,
  guardStreamingResponse,
  isStreamingContentType,
  buildThreatItem,
  buildRequestItem,
  sendEvents,
  EDGE_SAFE_FEATURES,
  type SilkerOptions,
  type TelemetryConfig,
  type ThreatInfo,
} from '../../src/core';

export interface Env {
  SILKER_API_KEY: string;
  SILKER_APP_ID?: string;
  SILKER_ENDPOINT?: string;
  /** Origin do którego forwardujemy ruch (np. https://origin.example.com). */
  SILKER_TARGET?: string;
}

let configured = false;

function ensureConfigured(env: Env): void {
  if (configured) return;
  const options: SilkerOptions = {
    apiKey: env.SILKER_API_KEY,
    appId: env.SILKER_APP_ID,
    features: {
      ...EDGE_SAFE_FEATURES,
      // Banowanie IP wymaga stanu globalnego (KV/DO) - wyłączone w MVP edge.
      ipBanning: false,
    },
  };
  configureCore(options);
  configured = true;
}

function telemetryConfig(env: Env): TelemetryConfig {
  return {
    endpoint: env.SILKER_ENDPOINT || 'https://platform.silkerai.com',
    apiKey: env.SILKER_API_KEY,
    appId: env.SILKER_APP_ID,
  };
}

/** Forward do originu; przepisuje host na SILKER_TARGET (albo passthrough). */
async function forwardToOrigin(request: Request, env: Env): Promise<Response> {
  if (!env.SILKER_TARGET) {
    return fetch(request);
  }
  const incoming = new URL(request.url);
  const target = new URL(env.SILKER_TARGET);
  incoming.protocol = target.protocol;
  incoming.hostname = target.hostname;
  incoming.port = target.port;
  return fetch(new Request(incoming.toString(), request));
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const start = Date.now();
    try {
      ensureConfigured(env);

      const ip = request.headers.get('cf-connecting-ip') || undefined;
      const event = await eventFromRequest(request, ip);
      const result = inspectEvent(event);

      if (result.blocked && result.threat) {
        const item = buildThreatItem(event, result.threat, env.SILKER_APP_ID, Date.now() - start);
        ctx.waitUntil(sendEvents(telemetryConfig(env), [item]));

        return new Response(
          JSON.stringify({
            error: 'Request blocked by Silker AI',
            reason: 'Security threat detected',
            type: result.threat.type,
          }),
          { status: 403, headers: { 'content-type': 'application/json' } },
        );
      }

      const response = await forwardToOrigin(request, env);
      const contentType = response.headers.get('content-type');
      const item = buildRequestItem(event, response.status, Date.now() - start, env.SILKER_APP_ID);
      ctx.waitUntil(sendEvents(telemetryConfig(env), [item]));

      const reportLeak = (description: string): void => {
        const threat: ThreatInfo = { type: 'Data Leakage', severity: 'critical', description };
        ctx.waitUntil(
          sendEvents(telemetryConfig(env), [buildThreatItem(event, threat, env.SILKER_APP_ID, Date.now() - start)]),
        );
      };

      // Strumień LLM (SSE/ndjson): token-level guardrails z cut-off.
      if (EDGE_SAFE_FEATURES.streamingGuardrails !== false && isStreamingContentType(contentType) && response.body) {
        return guardStreamingResponse(response, {
          onDetect: (findings) =>
            reportLeak(`Sensitive data / policy violation in streamed response: ${findings.join(', ')}`),
        });
      }

      // Pozostałe odpowiedzi: skan klona w tle (telemetria), bez blokowania ścieżki.
      if (EDGE_SAFE_FEATURES.responseInspection !== false && response.body) {
        const clone = response.clone();
        ctx.waitUntil(
          (async () => {
            try {
              const text = await clone.text();
              const threat = inspectResponseLeakage(text, contentType);
              if (threat) reportLeak(threat.description);
            } catch {
              // Inspekcja best-effort.
            }
          })(),
        );
      }

      return response;
    } catch {
      // Fail-open: nigdy nie psujemy aplikacji usera.
      try {
        return await forwardToOrigin(request, env);
      } catch {
        return fetch(request);
      }
    }
  },
};
