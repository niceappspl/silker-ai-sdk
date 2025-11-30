import { SilkerEvent } from '../../types';

/**
 * Wykrywa potencjalne ataki IDOR (Insecure Direct Object Reference).
 * Sprawdza czy ID w URL są podejrzane lub niezgodne z ID w payloadzie.
 * @param event - Zdarzenie do sprawdzenia
 * @param payload - Opcjonalny payload żądania
 * @returns true jeśli wykryto potencjalny atak IDOR, false w przeciwnym razie
 */
export function detectIdorAttack(event: SilkerEvent, payload?: any): boolean {
  if (!event.url) return false;

  const idorPatterns = [
    /\/user\/(-?\d+)/i,
    /\/account\/(-?\d+)/i,
    /\/profile\/(-?\d+)/i,
    /\/data\/(-?\d+)/i,
    /\/record\/(-?\d+)/i
  ];

  for (const pattern of idorPatterns) {
    const match = event.url.match(pattern);
    if (match) {
      const idStr = match[1];
      const id = parseInt(idStr);
      if (id > 999999 || id < 0) {
        return true;
      }

      if (payload) {
        // Check if payload is a JSON string we need to parse, or an object
        let payloadObj = payload;
        if (typeof payload === 'string') {
            try {
                payloadObj = JSON.parse(payload);
            } catch(e) {
                // ignore parsing errors
            }
        }

        if (typeof payloadObj === 'object') {
            const payloadId = payloadObj.id || payloadObj.userId || payloadObj.accountId;
            if (payloadId && payloadId !== id) {
            return true;
            }
        }
      }
    }
  }

  return false;
}
