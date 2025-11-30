import { SilkerEvent, SilkerOptions } from '../types';
import { telemetry } from './telemetry';

/**
 * Wysyła alert do dashboardu Silker AI.
 * Działa w tle, nie blokuje wątku głównego.
 * 
 * @param event - Zdarzenie które wywołało alert
 * @param threatType - Typ zagrożenia (np. "SQL Injection", "XSS")
 * @param severity - Poziom zagrożenia
 * @param options - Opcje konfiguracyjne Silker
 */
export function sendAlertToDashboard(
  event: SilkerEvent,
  threatType: string,
  severity: 'critical' | 'high' | 'medium' | 'low',
  options: SilkerOptions
): void {
  try {
    telemetry.configure(options);

    const alertData = {
      type: threatType,
      severity,
      ip: event.ip || 'unknown',
      endpoint: event.url || '/',
      timestamp: new Date(event.timestamp || Date.now()).toISOString(),
      app_id: options.appId
    };

    telemetry.push('alert', '/api/dashboard/alerts', alertData);
  } catch (error) {
    if (options.debug) {
      console.error('🚨 Failed to queue alert:', error);
    }
  }
}

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
export function sendThreatToDashboard(
  event: SilkerEvent,
  threatType: string,
  severity: 'critical' | 'high' | 'medium' | 'low',
  blocked: boolean,
  description: string,
  options: SilkerOptions
): void {
  try {
    telemetry.configure(options);

    const threatData = {
      type: threatType,
      severity,
      blocked,
      description,
      app_id: options.appId
    };

    telemetry.push('threat', '/api/threats', threatData);
  } catch (error) {
    if (options.debug) {
      console.error('🚨 Failed to queue threat:', error);
    }
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
export function sendRequestToDashboard(
  event: SilkerEvent,
  statusCode: number,
  responseTime: number,
  options: SilkerOptions
): void {
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

    telemetry.push('request', '/api/requests', requestData);
  } catch (error) {
    if (options.debug) {
      console.error('🚨 Failed to queue request:', error);
    }
  }
}
