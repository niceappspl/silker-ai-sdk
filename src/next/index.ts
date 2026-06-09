/**
 * Adapter Next.js (App Router, Edge runtime) dla Silker.
 *
 * Reużywa edge-safe rdzeń (`../core`) - dokładnie ten sam silnik co Worker.
 * Ekspresowy middleware (`(req,res,next)`) NIE działa na Edge runtime; ten
 * adapter zwraca handler zgodny z `middleware.ts` App Routera:
 *   `(request: Request) => Promise<Response>`.
 *
 * Dependency na `next`:
 *   `next` jest OPCJONALNYM peerDependency. Aby SDK budowało się (`tsc`)
 *   i testowało bez zainstalowanego `next`, `next/server` jest ładowane
 *   leniwie przez `require('next/server')` w czasie wywołania (nie statyczny
 *   `import`). Dzięki temu kompilator nie próbuje rozwiązać typów `next/server`,
 *   a Jest może podmienić moduł przez `jest.mock('next/server', ...)`.
 */
import {
  configureCore,
  eventFromRequest,
  inspectEvent,
  buildThreatItem,
  buildRequestItem,
  sendEvents,
  EDGE_SAFE_FEATURES,
  type TelemetryConfig,
} from '../core';
import { resolveSilkerOptions } from '../config/env';
import { SilkerOptions } from '../types';

/** Minimalny kształt `NextResponse` którego używamy (unika twardej zależności od `next`). */
interface NextResponseStatic {
  next: () => Response;
  json: (body: unknown, init?: { status?: number }) => Response;
}

/**
 * Leniwie ładuje `NextResponse` z `next/server`.
 * `require` (a nie statyczny `import`) zachowuje zielony `tsc` bez `next`
 * i pozwala na `jest.mock('next/server')` w testach.
 */
function getNextResponse(): NextResponseStatic {
  const mod = require('next/server') as { NextResponse: NextResponseStatic };
  return mod.NextResponse;
}

let configured = false;

function resolveIp(request: Request): string | undefined {
  return (
    request.headers.get('x-real-ip') ||
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('cf-connecting-ip') ||
    undefined
  );
}

function telemetryConfig(options: SilkerOptions): TelemetryConfig {
  return {
    endpoint: options.endpoint || 'https://platform.silkerai.com',
    apiKey: options.apiKey || '',
    appId: options.appId,
  };
}

/**
 * Tworzy middleware Next.js (App Router / Edge runtime) dla Silker.
 *
 * Użycie w `middleware.ts`:
 * ```ts
 * import { nextMiddleware } from '@silker-ai/agent/next';
 * export const middleware = nextMiddleware();
 * ```
 *
 * Konfiguracja jest opcjonalna — `apiKey`/`appId`/`endpoint` są czytane z env
 * (`SILKER_API_KEY`, `SILKER_APP_ID`, `SILKER_ENDPOINT`) jeśli nie podano jawnie.
 * Bazowy zestaw funkcji to `EDGE_SAFE_FEATURES` (niskie false-positive na edge),
 * scalony z `options.features`. Adapter NIGDY nie rzuca — przy błędzie przepuszcza
 * żądanie (fail-open). Telemetria jest fire-and-forget (nie blokuje odpowiedzi).
 *
 * @param options - Opcje konfiguracyjne Silker (opcjonalne)
 * @returns Handler `(request: Request) => Promise<Response>` dla `middleware.ts`
 */
export function nextMiddleware(
  options: Partial<SilkerOptions> = {},
): (request: Request) => Promise<Response> {
  const resolved = resolveSilkerOptions({
    ...options,
    features: { ...EDGE_SAFE_FEATURES, ...options.features },
  });

  return async (request: Request): Promise<Response> => {
    const NextResponse = getNextResponse();
    const start = Date.now();
    try {
      // Konfiguracja rdzenia raz na proces (nie per request).
      if (!configured) {
        configureCore(resolved);
        configured = true;
      }

      const event = await eventFromRequest(request, resolveIp(request));
      const result = inspectEvent(event);

      if (result.blocked && result.threat) {
        const item = buildThreatItem(event, result.threat, resolved.appId, Date.now() - start);
        // Fire-and-forget: Edge runtime utrzymuje isolate krótko po response;
        // nie await-ujemy na ścieżce żądania.
        void sendEvents(telemetryConfig(resolved), [item]);

        return NextResponse.json(
          { error: 'Request blocked by Silker AI', type: result.threat.type },
          { status: 403 },
        );
      }

      const item = buildRequestItem(event, 200, Date.now() - start, resolved.appId);
      void sendEvents(telemetryConfig(resolved), [item]);
      // Parytet z Workerem: zdalna konfiguracja z dashboardu nie jest aplikowana
      // na warstwie edge (telemetria nie czyta odpowiedzi ingestu) — bez over-engineeringu.
      return NextResponse.next();
    } catch {
      // Fail-open: nigdy nie psujemy aplikacji usera.
      return NextResponse.next();
    }
  };
}
