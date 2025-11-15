import { SilkerEvent } from '../types';

const EXPOSED_FILES = [
  '/.git/config',
  '/.git/HEAD',
  '/.env',
  '/.env.local',
  '/.env.production',
  '/package.json',
  '/composer.json',
  '/requirements.txt',
  '/pom.xml',
  '/.dockerignore',
  '/Dockerfile',
  '/docker-compose.yml',
  '/.htaccess',
  '/web.config',
  '/.DS_Store',
  '/.idea/',
  '/.vscode/',
  '/backup.sql',
  '/dump.sql',
  '/database.sql'
];

export interface IntegrityIssue {
  type: 'missing_sri' | 'exposed_file' | 'unsigned_script' | 'tampered_resource';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  resource?: string;
}

export function checkSoftwareIntegrity(event: SilkerEvent): IntegrityIssue[] {
  const issues: IntegrityIssue[] = [];

  if (event.url) {
    const url = event.url.toLowerCase();

    for (const file of EXPOSED_FILES) {
      if (url.includes(file.toLowerCase())) {
        issues.push({
          type: 'exposed_file',
          severity: file.includes('.env') || file.includes('.git') ? 'critical' : 'high',
          description: `Exposed file detected: ${file}`,
          resource: file
        });
      }
    }
  }

  if (event.payload && typeof event.payload === 'string') {
    const payload = event.payload;

    if (payload.includes('<script') && !payload.includes('integrity=')) {
      const scriptMatches = payload.match(/<script[^>]*src=["']([^"']+)["']/gi);
      if (scriptMatches && scriptMatches.length > 0) {
        issues.push({
          type: 'missing_sri',
          severity: 'medium',
          description: 'Script tags without Subresource Integrity (SRI) detected'
        });
      }
    }

    if (payload.includes('<link') && payload.includes('stylesheet')) {
      const linkMatches = payload.match(/<link[^>]*href=["']([^"']+)["']/gi);
      if (linkMatches && linkMatches.length > 0) {
        const hasIntegrity = linkMatches.some(match => match.includes('integrity='));
        if (!hasIntegrity) {
          issues.push({
            type: 'missing_sri',
            severity: 'medium',
            description: 'Stylesheet links without Subresource Integrity (SRI) detected'
          });
        }
      }
    }
  }

  return issues;
}

export function validateSRI(html: string): { valid: boolean; missing: string[] } {
  const missing: string[] = [];
  
  const scriptPattern = /<script[^>]*src=["']([^"']+)["'][^>]*>/gi;
  const linkPattern = /<link[^>]*href=["']([^"']+)["'][^>]*>/gi;

  const scripts = html.matchAll(scriptPattern);
  for (const match of scripts) {
    const tag = match[0];
    if (!tag.includes('integrity=') && !match[1].startsWith('data:') && !match[1].startsWith('#')) {
      missing.push(`Script: ${match[1]}`);
    }
  }

  const links = html.matchAll(linkPattern);
  for (const match of links) {
    const tag = match[0];
    if (tag.includes('stylesheet') && !tag.includes('integrity=') && !match[1].startsWith('data:')) {
      missing.push(`Stylesheet: ${match[1]}`);
    }
  }

  return {
    valid: missing.length === 0,
    missing
  };
}

