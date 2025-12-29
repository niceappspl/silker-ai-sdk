import { SilkerEvent, SilkerOptions } from '../types';
import { telemetry } from './telemetry';
import { createLogger } from '../utils/logger';

/**
 * Wysyła threat do dashboardu Silker AI.
 * Działa w tle, nie blokuje wątku głównego.
 * 
 * @param event - Zdarzenie które wywołało threat
 * @param threatType - Typ zagrożenia
 * @param severity - Poziom zagrożenia
 * @param blocked - Czy threat został zablokowany
 * @param description - Opis threatu
 * @param options - Opcje konfiguracyjne Silker
 */
export async function sendThreatToDashboard(
  event: SilkerEvent,
  threatType: string,
  severity: 'critical' | 'high' | 'medium' | 'low',
  blocked: boolean,
  description: string,
  options: SilkerOptions,
  responseTime?: number
): Promise<void> {
  try {
    telemetry.configure(options);

    const threatData = {
      type: threatType,
      severity,
      blocked,
      description,
      ip: event.ip || 'unknown',
      endpoint: event.url || '/',
      method: event.method || 'UNKNOWN',
      headers: event.headers || {},
      body: event.payload || '',
      query: event.url.split('?')[1] || '',
      user_agent: event.userAgent || 'unknown',
      app_id: options.appId,
      response_time: responseTime,
      ip__banning_enabled: options.features?.ipBanning !== false
    };

    await telemetry.push('threat', '/api/threats', threatData);
  } catch (error) {
    const logger = createLogger(options);
    logger.error('Failed to queue threat:', error);
  }
}

/**
 * Wysyła request do dashboardu Silker AI dla analityki.
 * Działa w tle, nie blokuje wątku głównego.
 * 
 * @param event - Zdarzenie requestu
 * @param statusCode - Kod statusu HTTP
 * @param responseTime - Czas odpowiedzi w ms
 * @param options - Opcje konfiguracyjne Silker
 */
export async function sendRequestToDashboard(
  event: SilkerEvent,
  statusCode: number,
  responseTime: number,
  options: SilkerOptions
): Promise<void> {
  try {
    telemetry.configure(options);

    const requestData = {
      endpoint: event.url || '/',
      method: event.method || 'GET',
      status_code: statusCode,
      response_time: responseTime,
      ip: event.ip || 'unknown',
      user_agent: event.userAgent || 'unknown',
      app_id: options.appId
    };

    await telemetry.push('request', '/api/requests', requestData);
  } catch (error) {
    const logger = createLogger(options);
    logger.error('Failed to queue request:', error);
  }
}
