import { SilkerEvent } from '../types';
import { isAuthEndpoint } from './authContext';

const DEFAULT_CREDENTIALS = [
  { user: 'admin', pass: 'admin' },
  { user: 'administrator', pass: 'administrator' },
  { user: 'root', pass: 'root' },
  { user: 'admin', pass: 'password' },
  { user: 'admin', pass: '123456' },
  { user: 'admin', pass: 'admin123' },
  { user: 'test', pass: 'test' },
  { user: 'guest', pass: 'guest' },
  { user: 'user', pass: 'user' }
];

const WEAK_PASSWORD_PATTERNS = [
  /^[0-9]{1,8}$/,
  /^[a-z]{1,8}$/i,
  /^[A-Z]{1,8}$/,
  /^(password|123456|admin|qwerty|letmein|welcome|monkey|1234567890|abc123)$/i,
  /^(.)\1+$/,
  /^.{1,5}$/
];

export interface AuthenticationIssue {
  type: 'default_credentials' | 'weak_password' | 'missing_mfa' | 'session_fixation' | 'no_rate_limit';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
}

export function detectAuthenticationFailures(event: SilkerEvent): AuthenticationIssue[] {
  const issues: AuthenticationIssue[] = [];
  const url = (event.url || '').toLowerCase();
  let payload: Record<string, unknown> | null = null;

  if (event.payload && typeof event.payload === 'object') {
    payload = event.payload as Record<string, unknown>;
  } else if (typeof event.payload === 'string' && event.payload.trim().startsWith('{')) {
    try {
      const parsed = JSON.parse(event.payload);
      if (parsed && typeof parsed === 'object') {
        payload = parsed as Record<string, unknown>;
      }
    } catch {
      // ignore invalid JSON
    }
  }

  if (isAuthEndpoint(url)) {
    if (payload) {
      const username = payload.username || payload.user || payload.email || payload.login;
      const password = payload.password || payload.pass || payload.pwd;

      if (username && password) {
        for (const cred of DEFAULT_CREDENTIALS) {
          if (username.toString().toLowerCase() === cred.user && password === cred.pass) {
            issues.push({
              type: 'default_credentials',
              severity: 'low',
              description: `Default credentials detected: ${cred.user}/${cred.pass}`
            });
          }
        }

        if (typeof password === 'string') {
          if (isWeakPassword(password)) {
            issues.push({
              type: 'weak_password',
              severity: 'low',
              description: 'Weak password detected'
            });
          }
        }
      }

      if (!payload.mfa && !payload.totp && !payload['2fa'] && !payload.twoFactor) {
        issues.push({
          type: 'missing_mfa',
          severity: 'medium',
          description: 'Multi-factor authentication not detected'
        });
      }
    }

    if (event.method === 'POST') {
      const headers = event.headers || {};
      if (!headers['x-ratelimit-limit'] && !headers['rate-limit']) {
        issues.push({
          type: 'no_rate_limit',
          severity: 'medium',
          description: 'No rate limiting detected on authentication endpoint'
        });
      }
    }
  }

  if (url.includes('/session') || url.includes('/token')) {
    const headers = event.headers || {};
    const sessionId = headers['x-session-id'] || headers['session-id'] || 
                     (payload && typeof payload === 'object' ? payload.sessionId : null);

    if (sessionId && typeof sessionId === 'string') {
      if (sessionId.length < 16) {
        issues.push({
          type: 'session_fixation',
          severity: 'high',
          description: 'Weak session ID detected (potential session fixation vulnerability)'
        });
      }

      if (/^\d+$/.test(sessionId)) {
        issues.push({
          type: 'session_fixation',
          severity: 'high',
          description: 'Predictable session ID detected (sequential numbers)'
        });
      }
    }
  }

  return issues;
}

export function isWeakPassword(password: string): boolean {
  if (!password || password.length < 8) {
    return true;
  }

  for (const pattern of WEAK_PASSWORD_PATTERNS) {
    if (pattern.test(password)) {
      return true;
    }
  }

  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);

  const complexityScore = [hasUpper, hasLower, hasNumber, hasSpecial].filter(Boolean).length;
  if (complexityScore < 2) {
    return true;
  }

  return false;
}

export function detectDefaultCredentials(username: string, password: string): boolean {
  for (const cred of DEFAULT_CREDENTIALS) {
    if (username.toLowerCase() === cred.user && password === cred.pass) {
      return true;
    }
  }
  return false;
}

