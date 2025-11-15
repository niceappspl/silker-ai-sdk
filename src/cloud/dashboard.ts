import axios from 'axios';
import { SilkerEvent, SilkerOptions } from '../types';

/**
 * Wysyła alert do dashboardu Silker AI.
 * @param event - Zdarzenie które wywołało alert
 * @param threatType - Typ zagrożenia (np. "SQL Injection", "XSS")
 * @param severity - Poziom zagrożenia
 * @param options - Opcje konfiguracyjne Silker
 * @returns ID alertu lub null w przypadku błędu
 */
export async function sendAlertToDashboard(
  event: SilkerEvent,
  threatType: string,
  severity: 'critical' | 'high' | 'medium' | 'low',
  options: SilkerOptions
): Promise<string | null> {
  try {
    const isDev = process.env.NODE_ENV === 'development' || process.env.SILKER_DEV === 'true';
    let dashboardEndpoint = options.endpoint || (isDev ? 'http://localhost:3000' : 'https://api.silkerai.com');
    if (dashboardEndpoint.includes('/api')) {
      dashboardEndpoint = dashboardEndpoint.replace('/api', '');
    }
    dashboardEndpoint = dashboardEndpoint.replace(/\/$/, '');
    const alertEndpoint = `${dashboardEndpoint}/api/dashboard/alerts`;

    const alertData = {
      type: threatType,
      severity,
      ip: event.ip || 'unknown',
      endpoint: event.url || '/',
      timestamp: new Date(event.timestamp || Date.now()).toISOString(),
      app_id: options.appId
    };

    const response = await axios.post(alertEndpoint, alertData, {
      headers: {
        'x-api-key': options.apiKey,
        'Content-Type': 'application/json'
      },
      timeout: 5000
    });

    return response.data?.data?.id || null;
  } catch (error) {
    if (options.debug) {
      console.log('🚨 Failed to send alert to dashboard:', (error as Error).message);
    }
    return null;
  }
}

/**
 * Wysyła threat do dashboardu Silker AI.
 * @param event - Zdarzenie które wywołało threat
 * @param threatType - Typ zagrożenia
 * @param severity - Poziom zagrożenia
 * @param blocked - Czy threat został zablokowany
 * @param description - Opis threatu
 * @param options - Opcje konfiguracyjne Silker
 * @returns ID threatu lub null w przypadku błędu
 */
export async function sendThreatToDashboard(
  event: SilkerEvent,
  threatType: string,
  severity: 'critical' | 'high' | 'medium' | 'low',
  blocked: boolean,
  description: string,
  options: SilkerOptions
): Promise<string | null> {
  try {
    const isDev = process.env.NODE_ENV === 'development' || process.env.SILKER_DEV === 'true';
    let dashboardEndpoint = options.endpoint || (isDev ? 'http://localhost:3000' : 'https://api.silkerai.com');
    if (dashboardEndpoint.includes('/api')) {
      dashboardEndpoint = dashboardEndpoint.replace('/api', '');
    }
    dashboardEndpoint = dashboardEndpoint.replace(/\/$/, '');
    const threatEndpoint = `${dashboardEndpoint}/api/threats`;

    const threatData = {
      type: threatType,
      severity,
      blocked,
      description,
      app_id: options.appId
    };

    const response = await axios.post(threatEndpoint, threatData, {
      headers: {
        'x-api-key': options.apiKey,
        'Content-Type': 'application/json'
      },
      timeout: 5000
    });

    return response.data?.data?.id || null;
  } catch (error) {
    if (options.debug) {
      console.log('🚨 Failed to send threat to dashboard:', (error as Error).message);
    }
    return null;
  }
}

/**
 * Wysyła request do dashboardu Silker AI dla analityki.
 * @param event - Zdarzenie requestu
 * @param statusCode - Kod statusu HTTP
 * @param responseTime - Czas odpowiedzi w ms
 * @param options - Opcje konfiguracyjne Silker
 * @returns ID requestu lub null w przypadku błędu
 */
export async function sendRequestToDashboard(
  event: SilkerEvent,
  statusCode: number,
  responseTime: number,
  options: SilkerOptions
): Promise<string | null> {
  try {
    const isDev = process.env.NODE_ENV === 'development' || process.env.SILKER_DEV === 'true';
    let dashboardEndpoint = options.endpoint || (isDev ? 'http://localhost:3000' : 'https://api.silkerai.com');
    if (dashboardEndpoint.includes('/api')) {
      dashboardEndpoint = dashboardEndpoint.replace('/api', '');
    }
    dashboardEndpoint = dashboardEndpoint.replace(/\/$/, '');
    const requestEndpoint = `${dashboardEndpoint}/api/requests`;

    const requestData = {
      endpoint: event.url || '/',
      method: event.method || 'GET',
      status_code: statusCode,
      response_time: responseTime,
      ip: event.ip || 'unknown',
      user_agent: event.userAgent || 'unknown',
      app_id: options.appId
    };

    const response = await axios.post(requestEndpoint, requestData, {
      headers: {
        'x-api-key': options.apiKey,
        'Content-Type': 'application/json'
      },
      timeout: 5000
    });

    return response.data?.data?.id || null;
  } catch (error) {
    if (options.debug) {
      console.log('🚨 Failed to send request to dashboard:', (error as Error).message);
    }
    return null;
  }
}

