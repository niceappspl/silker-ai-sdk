import { SilkerEvent } from '../types';

// Database of known malicious IPs (Example list - in production this would be synced from API)
const knownThreatIPs = new Set([
  '185.220.101.1', '185.220.101.2',
  '104.236.0.0', '104.236.255.255',
]);

// Database of known malicious domains (Example list)
const knownMaliciousDomains = new Set([
  'malicious-site.com', 'phishing-domain.net', 'malware-host.org',
]);

/**
 * Sprawdza zdarzenie pod kątem znanych zagrożeń z bazy threat intelligence.
 * Weryfikuje IP, domeny i user-agenty przeciwko znanym zagrożeniom.
 * @param event - Zdarzenie do sprawdzenia
 * @returns Obiekt z flagą zagrożenia i listą szczegółów
 */
export function checkThreatIntelligence(event: SilkerEvent): { threat: boolean; details: string[] } {
  const details: string[] = [];

  // IP Check
  if (event.ip && knownThreatIPs.has(event.ip)) {
    details.push(`IP ${event.ip} flagged in threat intelligence`);
  }

  // Domain/URL Check
  if (event.url) {
    try {
      // Normalize URL to check hostname against list
      const url = new URL(event.url.startsWith('http') ? event.url : `https://${event.url}`);
      if (knownMaliciousDomains.has(url.hostname)) {
        details.push(`Domain ${url.hostname} flagged as malicious`);
      }
    } catch (error) {
      // Ignore invalid URLs
    }
  }

  // User-Agent Check (Security Scanners)
  if (event.userAgent) {
    const suspiciousAgents = [
      'sqlmap', 'nikto', 'dirbuster', 'gobuster',
      'masscan', 'zmap', 'acunetix', 'openvas'
    ];

    const agent = event.userAgent.toLowerCase();
    for (const scanner of suspiciousAgents) {
      if (agent.includes(scanner)) {
        details.push(`User agent indicates security scanner: ${scanner}`);
        break;
      }
    }
  }

  return { threat: details.length > 0, details };
}
