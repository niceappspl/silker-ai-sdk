import { SilkerEvent } from '../types';

const WEAK_CIPHERS = [
  'RC4', 'MD5', 'SHA1', 'DES', '3DES', 'RC2',
  'NULL', 'EXPORT', 'ANON', 'ADH', 'LOW', 'MEDIUM'
];

const WEAK_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'];

export interface CryptographicCheckResult {
  valid: boolean;
  issues: string[];
  tlsVersion?: string;
  cipherSuite?: string;
}

export function checkCryptographicFailures(event: SilkerEvent): CryptographicCheckResult {
  const issues: string[] = [];
  const headers = event.headers || {};

  const url = event.url || '';
  const isHttps = url.startsWith('https://');

  if (!isHttps && (event.method === 'POST' || event.method === 'PUT' || event.method === 'PATCH')) {
    issues.push('Sensitive operations over HTTP instead of HTTPS');
  }

  if (headers['strict-transport-security']) {
    const hsts = headers['strict-transport-security'].toString();
    if (!hsts.includes('max-age') || hsts.includes('max-age=0')) {
      issues.push('HSTS header missing or misconfigured');
    }
  } else if (isHttps) {
    issues.push('Missing HSTS header');
  }

  if (event.payload && typeof event.payload === 'string') {
    const payload = event.payload.toLowerCase();
    
    const creditCardPattern = /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/;
    if (creditCardPattern.test(payload)) {
      issues.push('Potential credit card data in payload');
    }

    const ssnPattern = /\b\d{3}-\d{2}-\d{4}\b/;
    if (ssnPattern.test(payload)) {
      issues.push('Potential SSN data in payload');
    }

    if (payload.includes('password') && !payload.includes('hashed') && !payload.includes('encrypted')) {
      if (payload.match(/password['":\s]*=['":\s]*[^,\s}]+/i)) {
        issues.push('Potential plaintext password in payload');
      }
    }
  }

  return {
    valid: issues.length === 0,
    issues
  };
}

export function detectWeakEncryption(headers?: any): boolean {
  if (!headers) return false;

  const serverHeader = headers['server'] || headers['Server'] || '';
  const poweredBy = headers['x-powered-by'] || headers['X-Powered-By'] || '';

  const combined = (serverHeader + ' ' + poweredBy).toUpperCase();

  for (const weakCipher of WEAK_CIPHERS) {
    if (combined.includes(weakCipher)) {
      return true;
    }
  }

  for (const weakProtocol of WEAK_PROTOCOLS) {
    if (combined.includes(weakProtocol)) {
      return true;
    }
  }

  return false;
}

export function validateTlsVersion(tlsVersion?: string): boolean {
  if (!tlsVersion) return false;

  const version = tlsVersion.toUpperCase();
  return version.includes('TLSV1.2') || version.includes('TLSV1.3');
}

