import { SilkerOptions } from '../types';
import { Logger } from '../utils/logger';

let missingApiKeyWarned = false;

/**
 * Buduje finalne opcje SDK: jawne opcje > zmienne środowiskowe > wartości domyślne.
 * Endpoint pozostaje undefined jeśli nie podano - domyślny URL wybiera warstwa telemetrii.
 * @param options - Częściowe opcje przekazane przez użytkownika
 * @returns Opcje z rozwiązanym apiKey, appId i endpoint
 */
export function resolveSilkerOptions(options: Partial<SilkerOptions> = {}): SilkerOptions {
  return {
    ...options,
    apiKey: options.apiKey ?? process.env.SILKER_API_KEY,
    appId: options.appId ?? process.env.SILKER_APP_ID,
    endpoint: options.endpoint ?? process.env.SILKER_ENDPOINT,
  };
}

/**
 * Loguje ostrzeżenie o braku klucza API - tylko raz na proces, nie per request.
 * SDK działa wtedy w trybie detection-only (bez telemetrii).
 * @param logger - Logger do wypisania ostrzeżenia
 */
export function warnMissingApiKeyOnce(logger: Logger): void {
  if (missingApiKeyWarned) {
    return;
  }
  missingApiKeyWarned = true;
  logger.warn(
    '[Silker SDK] No API key resolved (options.apiKey or SILKER_API_KEY env). ' +
    'Running in detection-only mode - telemetry to the Silker platform is disabled.'
  );
}

/**
 * Resetuje flagę ostrzeżenia o braku klucza API.
 * TYLKO DO UŻYTKU W TESTACH!
 * @internal
 */
export function resetMissingApiKeyWarning(): void {
  missingApiKeyWarned = false;
}
