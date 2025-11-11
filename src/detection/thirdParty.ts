import { VibeGuardEvent } from '../types';

/**
 * Wykrywa ryzyka związane z integracjami zewnętrznymi.
 * Sprawdza czy żądania kierują się do podejrzanych domen lub webhooków.
 * @param event - Zdarzenie do sprawdzenia
 * @returns Obiekt z flagą ryzyka i listą znalezionych problemów
 */
export function detectThirdPartyRisks(event: VibeGuardEvent): { risky: boolean; issues: string[] } {
  const issues: string[] = [];

  if (!event.url) return { risky: false, issues };

  const url = event.url.toLowerCase();
  const payload = event.payload ? event.payload.toLowerCase() : '';

  const riskyDomains = [
    'pastebin.com', 'transfer.sh', '0bin.net',
    'webhook.site', 'requestbin.com', 'httpbin.org',
    'ngrok.io', 'localtunnel.me',
  ];

  for (const domain of riskyDomains) {
    if (url.includes(domain)) {
      issues.push(`Risky third-party service detected: ${domain}`);
    }
  }

  if (url.includes('webhook') || url.includes('callback')) {
    try {
      let urlToParse = event.url;
      if (!urlToParse.startsWith('http://') && !urlToParse.startsWith('https://')) {
        urlToParse = `https://${urlToParse}`;
      }
      const urlObj = new URL(urlToParse);
      const domain = urlObj.hostname.toLowerCase();

      if (!domain || domain.includes(' ') || !domain.includes('.')) {
        issues.push('Invalid webhook URL format');
        return { risky: true, issues };
      }

      const allowedDomains = [
        'hooks.slack.com', 'discord.com', 'webhook.site',
        'api.github.com', 'gitlab.com', 'bitbucket.org',
        'zapier.com', 'ifttt.com', 'make.com'
      ];

      const isAllowed = allowedDomains.some(allowed => domain.includes(allowed.toLowerCase()));
      
      if (!isAllowed) {
        const isRiskySlackDiscord = url.includes('slack.com/webhook') || url.includes('discord.com/api/webhooks');
        if (!isRiskySlackDiscord) {
          issues.push(`Unexpected webhook destination: ${domain}`);
        }
      }
    } catch (error) {
      issues.push('Invalid webhook URL format');
    }
  }

  if (payload && (url.includes('api.') || url.includes('webhook'))) {
    const apiKeyPatterns = [
      /api[_-]?key[=:]\s*['"]?([^'"\s&]{20,})['"]?/gi,
      /bearer\s+([a-zA-Z0-9_\-\.]{20,})/gi,
      /authorization[_-]?[=:]\s*['"]?bearer\s+([a-zA-Z0-9_\-\.]{20,})['"]?/gi,
    ];

    for (const pattern of apiKeyPatterns) {
      if (pattern.test(payload)) {
        issues.push('Potential API key exposure in third-party request');
        break;
      }
    }
  }

  if (event.method === 'POST' && payload) {
    if (payload.length > 10000) {
      issues.push('Large payload in third-party request - potential data exfiltration');
    }

    const sensitivePatterns = [
      /password|secret|token|key|credential/i,
      /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/,
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
    ];

    for (const pattern of sensitivePatterns) {
      if (pattern.test(payload)) {
        issues.push('Sensitive data detected in third-party request');
        break;
      }
    }
  }

  return { risky: issues.length > 0, issues };
}

/**
 * Wykrywa potencjalne ataki związane z integracjami zewnętrznymi.
 * @param event - Zdarzenie do sprawdzenia
 * @returns true jeśli wykryto potencjalny atak związany z integracjami zewnętrznymi, false w przeciwnym razie
 */
export function detectThirdPartyAttack(event: VibeGuardEvent): boolean {
  if (!event.url || event.url.includes('localhost') || event.url.includes('127.0.0.1')) {
    return false;
  }

  const riskCheck = detectThirdPartyRisks(event);
  return riskCheck.risky;
}

