import { SilkerEvent } from '../types';
import { FileUploadEvent } from '../types/metrics';

/**
 * Edge-safe dekodowanie base64 do bajtów (działa w Cloudflare Worker, Node i przeglądarce).
 * Nie używa Node `Buffer`, dzięki czemu moduł jest przenośny na runtime V8 (edge).
 */
function base64ToBytes(b64: string): Uint8Array {
  try {
    // Strip data-URL prefix i białe znaki; uzupełnij padding (forgiving, jak Buffer).
    let clean = b64.replace(/^data:[^;]*;base64,/, '').replace(/[^A-Za-z0-9+/=]/g, '');
    const pad = clean.length % 4;
    if (pad === 1) {
      // Niepoprawna długość base64 - brak sensownych bajtów do analizy.
      return new Uint8Array(0);
    }
    if (pad > 0) {
      clean = clean.padEnd(clean.length + (4 - pad), '=');
    }
    const binary = atob(clean);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return new Uint8Array(0);
  }
}

/**
 * Waliduje upload pliku pod kątem bezpieczeństwa.
 * Sprawdza rozmiar, typ MIME, magic bytes, nazwę pliku i zawartość.
 * @param event - Zdarzenie zawierające informacje o uploadzie pliku
 * @returns Obiekt z flagą bezpieczeństwa i listą znalezionych problemów
 */
export function validateFileUpload(event: SilkerEvent): { safe: boolean; issues: string[] } {
  const issues: string[] = [];

  let filename = '';
  let contentType = '';
  let size = 0;
  let content = '';

  try {
    // Attempt to parse payload if it's a string JSON, usually from middleware
    const payload = event.payload ? JSON.parse(event.payload) : {};

    if (payload.file || payload.files) {
      const fileData = payload.file || payload.files[0];
      filename = fileData?.filename || fileData?.name || '';
      contentType = fileData?.contentType || fileData?.type || '';
      size = fileData?.size || 0;
      content = fileData?.content || fileData?.data || '';
    }

    // Check for multipart uploads without actual file metadata (often bypass attempt)
    const contentTypeHeader = event.headers?.['content-type'] || event.headers?.['Content-Type'] || '';
    if (contentTypeHeader.includes('multipart/form-data')) {
      if (!filename && !contentType) {
        issues.push('Multipart upload detected but no file information provided');
      }
    }

    // Size validation (10MB hard limit for analysis)
    const maxSize = 10 * 1024 * 1024;
    if (size > maxSize) {
      issues.push(`File size ${size} bytes exceeds maximum allowed size ${maxSize} bytes`);
    }

    // Filename validation
    if (filename) {
      const dangerousPatterns = [
        /\.\./, // Path traversal
        /^[.-]/, // Hidden files or starting with dash
        /[<>:"|?*]/, // Windows reserved chars
        /[\x00-\x1f]/, // Control chars
        /com[1-9]|lpt[1-9]|con|prn|aux|nul/i, // Windows reserved names
      ];

      for (const pattern of dangerousPatterns) {
        if (pattern.test(filename)) {
          issues.push(`Dangerous filename pattern detected: ${filename}`);
          break;
        }
      }

      if (filename.length > 255) {
        issues.push('Filename too long (max 255 characters)');
      }
    }

    // Content-Type validation
    if (contentType) {
      const allowedTypes = [
        'image/jpeg', 'image/png', 'image/gif', 'image/webp',
        'application/pdf', 'text/plain', 'application/json',
        'application/zip', 'application/x-zip-compressed',
        'text/csv', 'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      ];

      if (!allowedTypes.includes(contentType.toLowerCase())) {
        issues.push(`Content type '${contentType}' not in allowed types list`);
      }
    }

    // Magic Bytes & Content Analysis (edge-safe, no Node Buffer)
    if (content && typeof content === 'string') {
      const bytes = base64ToBytes(content);

      const exeSignatures: number[][] = [
        [0x4D, 0x5A], // MZ (DOS/PE)
        [0x7F, 0x45, 0x4C, 0x46], // ELF (Linux)
        [0x23, 0x21], // #! (Shebang)
        [0xCA, 0xFE, 0xBA, 0xBE], // Java Class
      ];

      const startsWith = (signature: number[]): boolean =>
        signature.every((b, i) => bytes[i] === b);

      for (const signature of exeSignatures) {
        if (startsWith(signature)) {
          issues.push('Executable file detected - potential malware');
          break;
        }
      }

      // Check for scripts in non-script files (XSS via file upload)
      if (!contentType.includes('html') && !contentType.includes('text')) {
        const contentStr = new TextDecoder('utf-8', { fatal: false }).decode(bytes.slice(0, 100));
        if (contentStr.includes('<script') || contentStr.includes('javascript:') || contentStr.includes('onload=')) {
          issues.push('Script content detected in non-script file');
        }
      }
    }

    // Double check path traversal
    if (filename.includes('../') || filename.includes('..\\')) {
      issues.push('Path traversal detected in filename');
    }

  } catch (error) {
    // Fail open or closed? For security, we should probably flag it.
    issues.push('File upload validation failed');
  }

  return { safe: issues.length === 0, issues };
}

/**
 * Wykrywa potencjalne ataki związane z uploadem plików.
 * Sprawdza czy żądanie dotyczy uploadu i czy plik jest bezpieczny.
 * @param event - Zdarzenie do sprawdzenia
 * @returns true jeśli wykryto potencjalny atak związany z uploadem, false w przeciwnym razie
 */
export function detectFileUploadAttack(event: SilkerEvent): boolean {
  const url = event.url.toLowerCase();
  const method = event.method;

  // Heuristic to identify file upload endpoints
  if (method === 'POST' &&
      (url.includes('/upload') || url.includes('/file') || url.includes('/media') ||
       event.headers?.['content-type']?.includes('multipart'))) {

    const validation = validateFileUpload(event);

    if (!validation.safe) {
      return true;
    }
  }

  return false;
}
