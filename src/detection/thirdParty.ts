import { SilkerEvent } from '../types';

/**
 * Outbound egress guard — blokuje tylko na podstawie docelowego URL wychodzącego
 * fetch(), bez heurystyk payloadu (password/token w body to data leakage, nie third-party).
 *
 * Działa WYŁĄCZNIE gdy event.direction === 'outgoing' (fetch hook).
 * Incoming Express (/api/login, /api/webhook) — poza zakresem tego modułu.
 */

const EXFIL_DENYLIST = [
  'pastebin.com',
  'transfer.sh',
  '0bin.net',
  'webhook.site',
  'requestbin.com',
  'httpbin.org',
  'ngrok.io',
  'localtunnel.me',
];

const WEBHOOK_ALLOWLIST = [
  'hooks.slack.com',
  'discord.com',
  'api.github.com',
  'gitlab.com',
  'bitbucket.org',
  'zapier.com',
  'ifttt.com',
  'make.com',
];

function parseOutboundHostname(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function isDeniedExfilHost(hostname: string): boolean {
  return EXFIL_DENYLIST.some(domain => hostname === domain || hostname.endsWith(`.${domain}`));
}

function isAllowedWebhookHost(hostname: string): boolean {
  return WEBHOOK_ALLOWLIST.some(allowed => hostname === allowed || hostname.endsWith(`.${allowed}`));
}

function looksLikeWebhookUrl(url: string): boolean {
  const lower = url.toLowerCase();
  return lower.includes('/webhook') || lower.includes('/callback') || lower.includes('webhook.');
}

/**
 * Wykrywa ryzyka egressu do niezaufanych hostów (tylko outbound + absolute URL).
 */
export function detectThirdPartyRisks(event: SilkerEvent): { risky: boolean; issues: string[] } {
  const issues: string[] = [];

  if (event.direction !== 'outgoing') {
    return { risky: false, issues };
  }

  const url = event.url;
  if (!url || (!url.startsWith('http://') && !url.startsWith('https://'))) {
    return { risky: false, issues };
  }

  const hostname = parseOutboundHostname(url);
  if (!hostname) {
    return { risky: false, issues };
  }

  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return { risky: false, issues };
  }

  for (const domain of EXFIL_DENYLIST) {
    if (hostname === domain || hostname.endsWith(`.${domain}`)) {
      issues.push(`Known exfiltration host blocked: ${domain}`);
    }
  }

  if (looksLikeWebhookUrl(url) && !isAllowedWebhookHost(hostname) && !isDeniedExfilHost(hostname)) {
    issues.push(`Webhook egress to non-allowlisted host: ${hostname}`);
  }

  return { risky: issues.length > 0, issues };
}

export function detectThirdPartyAttack(event: SilkerEvent): boolean {
  if (!event.url || event.direction !== 'outgoing') {
    return false;
  }

  return detectThirdPartyRisks(event).risky;
}
