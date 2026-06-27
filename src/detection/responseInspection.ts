/**
 * Inspekcja WYCHODZĄCYCH odpowiedzi pod kątem wycieku danych wrażliwych.
 *
 * Skanuje treść odpowiedzi (zanim trafi do klienta) reużywając `detectDataLeakage`
 * (klucze API, sekrety, JWT, karty, klucze prywatne, connection stringi) oraz
 * wzorce PII (email/telefon). Edge-safe: czysty string match, bez Node API.
 *
 * Powłoki (fetch hook / Worker / kontener) wołają to po otrzymaniu odpowiedzi z
 * originu/upstreamu i raportują znaleziska jako zdarzenie "Data Leakage".
 */
import { detectDataLeakage } from './dataLeakage';

/** Domyślny limit treści odpowiedzi branej do skanu (perf/latencja). */
export const DEFAULT_RESPONSE_SCAN_BYTES = 256 * 1024;

const EMAIL_PATTERN = /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g;
const PHONE_PATTERN = /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/g;

/**
 * Typy treści, które ma sens skanować jako tekst. Binaria (obrazy, wideo, pliki)
 * są pomijane - nie zawierają sekretów w formie tekstowej, a skan byłby kosztowny.
 */
const SCANNABLE_CONTENT_TYPE = /(application\/(json|xml|.*\+json|.*\+xml|javascript|x-ndjson)|text\/|application\/x-www-form-urlencoded|event-stream)/i;

/**
 * Czy odpowiedź o danym Content-Type warto skanować jako tekst.
 * Brak nagłówka traktujemy jako skanowalny (zachowawczo - lepiej sprawdzić).
 */
export function isScannableContentType(contentType?: string | null): boolean {
  if (!contentType) return true;
  return SCANNABLE_CONTENT_TYPE.test(contentType);
}

export interface ResponseLeakResult {
  leaked: boolean;
  findings: string[];
}

/**
 * Skanuje tekst odpowiedzi pod kątem wycieku sekretów i PII.
 * @param text - Treść odpowiedzi (tekst)
 * @param maxBytes - Limit skanowanej długości (domyślnie DEFAULT_RESPONSE_SCAN_BYTES)
 */
export function inspectResponseText(text: string, maxBytes: number = DEFAULT_RESPONSE_SCAN_BYTES): ResponseLeakResult {
  if (!text) return { leaked: false, findings: [] };
  const content = text.length > maxBytes ? text.slice(0, maxBytes) : text;

  // Sekrety/klucze/PII strukturalne - reużycie sprawdzonego detektora (gałąź `response`).
  const leakage = detectDataLeakage(undefined, content);
  const findings = [...leakage.findings];

  // PII tekstowe (email/telefon) - istotne dla odpowiedzi LLM/API, nie pokryte w detectDataLeakage.
  if (findings.length < 10) {
    const emails = content.match(EMAIL_PATTERN);
    if (emails && emails.length > 0) {
      findings.push(`PII (email): ${emails.length} occurrence(s)`);
    }
  }
  if (findings.length < 10) {
    const phones = content.match(PHONE_PATTERN);
    if (phones && phones.length > 0) {
      findings.push(`PII (phone): ${phones.length} occurrence(s)`);
    }
  }

  return { leaked: findings.length > 0, findings: findings.slice(0, 10) };
}
