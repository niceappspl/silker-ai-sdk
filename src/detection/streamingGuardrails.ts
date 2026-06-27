/**
 * Token-level guardrails dla strumieniowanych odpowiedzi LLM (SSE / chunked).
 *
 * Owija `ReadableStream` odpowiedzi w `TransformStream`, który skanuje treść w locie
 * (sekrety/PII via inspectResponseText + udany jailbreak/wyciek promptu via
 * detectPromptInjection) i UCINA strumień zanim wrażliwy payload się dokończy.
 *
 * Boundary-safe: ostatnie `HOLDBACK` znaków jest wstrzymywane, aż zostaną
 * zeskanowane - sekret rozbity między chunkami nie wycieknie przedwcześnie.
 * Edge-safe: TransformStream/TextDecoder/TextEncoder (Worker, Node 18+).
 */
import { inspectResponseText } from './responseInspection';
import { detectPromptInjection } from './promptInjection';

/** Ile końcowych znaków wstrzymujemy do czasu skanu (pokrywa nasze wzorce). */
const HOLDBACK = 512;
/** Górny limit kumulatywnego okna skanu (perf). */
const MAX_SCAN = 64 * 1024;
/** Skanujemy dopiero po napłynięciu tylu nowych znaków (throttling dla strumieni tokenowych). */
const SCAN_STEP = 48;

const BLOCK_NOTICE =
  '\n\n[Silker AI] Response stopped: sensitive data or policy violation detected in model output.';

export interface GuardrailOptions {
  /** Limit kumulatywnego okna skanu (domyślnie 64KB). */
  maxScanBytes?: number;
  /** Callback wywoływany przy wykryciu (do telemetrii). */
  onDetect?: (findings: string[]) => void;
}

/** Czy Content-Type wskazuje strumień, który warto objąć guardrailami. */
export function isStreamingContentType(contentType?: string | null): boolean {
  if (!contentType) return false;
  return /event-stream|x-ndjson|stream\+json|application\/json-seq/i.test(contentType);
}

function scanForViolations(text: string): string[] {
  const leak = inspectResponseText(text);
  if (leak.leaked) return leak.findings;
  const inj = detectPromptInjection(text);
  if (inj.detected && (inj.severity === 'high' || inj.severity === 'critical')) {
    return [`LLM output policy violation: ${inj.patterns.slice(0, 3).join(', ')}`];
  }
  return [];
}

/**
 * Tworzy TransformStream skanujący strumień bajtów i ucinający go przy wykryciu.
 */
export function createGuardrailTransform(
  options: GuardrailOptions = {},
): TransformStream<Uint8Array, Uint8Array> {
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  const maxScan = options.maxScanBytes ?? MAX_SCAN;

  let pending = '';
  let scanned = '';
  let bytesSinceScan = 0;
  let tripped = false;

  const trip = (controller: TransformStreamDefaultController<Uint8Array>, findings: string[]): void => {
    tripped = true;
    options.onDetect?.(findings);
    controller.enqueue(encoder.encode(BLOCK_NOTICE));
    controller.terminate();
  };

  return new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      if (tripped) return;
      const text = decoder.decode(chunk, { stream: true });
      pending += text;
      bytesSinceScan += text.length;

      if (bytesSinceScan >= SCAN_STEP) {
        bytesSinceScan = 0;
        scanned += pending.slice(-maxScan);
        if (scanned.length > maxScan) scanned = scanned.slice(scanned.length - maxScan);
        const findings = scanForViolations(scanned);
        if (findings.length > 0) {
          trip(controller, findings);
          return;
        }
      }

      // Wypuszczamy wszystko poza holdbackiem (granica chunka).
      if (pending.length > HOLDBACK) {
        const flush = pending.slice(0, pending.length - HOLDBACK);
        pending = pending.slice(pending.length - HOLDBACK);
        controller.enqueue(encoder.encode(flush));
      }
    },
    flush(controller) {
      if (tripped) return;
      const tail = decoder.decode();
      if (tail) pending += tail;
      const findings = scanForViolations((scanned + pending).slice(-maxScan));
      if (findings.length > 0) {
        options.onDetect?.(findings);
        controller.enqueue(encoder.encode(BLOCK_NOTICE));
        return;
      }
      if (pending) controller.enqueue(encoder.encode(pending));
    },
  });
}

/**
 * Owija odpowiedź guardrailami strumieniowymi, jeśli ma strumieniowe body.
 * Zwraca NOWĄ odpowiedź z przepuszczonym strumieniem (te same nagłówki/status).
 * Gdy body jest null lub TransformStream niedostępny - zwraca oryginał bez zmian.
 */
export function guardStreamingResponse(
  response: Response,
  options: GuardrailOptions = {},
): Response {
  if (!response.body || typeof TransformStream === 'undefined') return response;
  try {
    const guarded = response.body.pipeThrough(createGuardrailTransform(options));
    return new Response(guarded, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  } catch {
    return response;
  }
}
