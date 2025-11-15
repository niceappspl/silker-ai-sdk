import { SilkerEvent } from '../types';
import { FileUploadEvent } from '../types/metrics';

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
  let content: Buffer | string = '';

  try {
    const payload = event.payload ? JSON.parse(event.payload) : {};

    if (payload.file || payload.files) {
      const fileData = payload.file || payload.files[0];
      filename = fileData?.filename || fileData?.name || '';
      contentType = fileData?.contentType || fileData?.type || '';
      size = fileData?.size || 0;
      content = fileData?.content || fileData?.data || '';
    }

    const contentTypeHeader = event.headers?.['content-type'] || event.headers?.['Content-Type'] || '';
    if (contentTypeHeader.includes('multipart/form-data')) {
      if (!filename && !contentType) {
        issues.push('Multipart upload detected but no file information provided');
      }
    }

    const maxSize = 10 * 1024 * 1024;
    if (size > maxSize) {
      issues.push(`File size ${size} bytes exceeds maximum allowed size ${maxSize} bytes`);
    }

    if (filename) {
      const dangerousPatterns = [
        /\.\./,
        /^[.-]/,
        /[<>:"|?*]/,
        /[\x00-\x1f]/,
        /com[1-9]|lpt[1-9]|con|prn|aux|nul/i,
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

    if (content && typeof content === 'string') {
      const buffer = Buffer.from(content, 'base64');
      const magicBytes = buffer.slice(0, 8);

      const exeSignatures = [
        Buffer.from([0x4D, 0x5A]),
        Buffer.from([0x7F, 0x45, 0x4C, 0x46]),
        Buffer.from([0x23, 0x21]),
        Buffer.from([0xCA, 0xFE, 0xBA, 0xBE]),
      ];

      for (const signature of exeSignatures) {
        if (magicBytes.slice(0, signature.length).equals(signature)) {
          issues.push('Executable file detected - potential malware');
          break;
        }
      }

      if (!contentType.includes('html') && !contentType.includes('text')) {
        const contentStr = buffer.toString('utf8', 0, 100);
        if (contentStr.includes('<script') || contentStr.includes('javascript:') || contentStr.includes('onload=')) {
          issues.push('Script content detected in non-script file');
        }
      }
    }

    if (filename.includes('../') || filename.includes('..\\')) {
      issues.push('Path traversal detected in filename');
    }

  } catch (error) {
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

