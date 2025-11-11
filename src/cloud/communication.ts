import axios from 'axios';
import { VibeGuardEvent, VibeGuardOptions, CloudResponse } from '../types';
import { sanitizeSensitiveData } from './sanitization';

/**
 * Wysyła zdarzenie do chmury VibeGuard w celu analizy AI.
 * Dane wrażliwe są automatycznie sanitizowane przed wysłaniem.
 * @param event - Zdarzenie do analizy
 * @param options - Opcje konfiguracyjne VibeGuard
 * @returns Odpowiedź z chmury lub null w przypadku błędu
 */
export async function sendToCloud(event: VibeGuardEvent, options: VibeGuardOptions): Promise<CloudResponse | null> {
  try {
    const endpoint = options.endpoint || 'https://vibeguard.cloudflareworkers.com/api';

    const sanitizedEvent = {
      ...event,
      payload: event.payload ? sanitizeSensitiveData(event.payload) : undefined,
      headers: event.headers ? sanitizeSensitiveData(event.headers) : undefined
    };

    const response = await axios.post(endpoint, sanitizedEvent, {
      headers: {
        'Authorization': `Bearer ${options.apiKey}`,
        'Content-Type': 'application/json',
        'X-VibeGuard-Version': '0.1.0'
      },
      timeout: 5000
    });

    (global as any).lastCloudContact = Date.now();

    return response.data;
  } catch (error) {
    if (options.debug) {
      console.log('🚨 VibeGuard cloud call failed:', (error as Error).message);
    }
    return null;
  }
}

