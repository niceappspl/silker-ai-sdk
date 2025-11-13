import { VibeGuardEvent } from '../types';

const KNOWN_VULNERABLE_VERSIONS: { [key: string]: string[] } = {
  'jquery': ['1.0.0', '1.1.0', '1.2.0', '1.3.0', '1.4.0', '1.5.0', '1.6.0', '1.7.0', '1.8.0', '1.9.0', '1.10.0', '1.11.0', '2.0.0', '2.1.0', '2.2.0'],
  'react': ['0.0.0', '0.1.0', '0.2.0', '0.3.0', '0.4.0', '0.5.0'],
  'angular': ['1.0.0', '1.1.0', '1.2.0'],
  'express': ['1.0.0', '2.0.0', '3.0.0'],
  'node': ['0.0.0', '0.1.0', '0.2.0']
};

const VULNERABLE_HEADERS = [
  'x-powered-by',
  'server',
  'x-aspnet-version',
  'x-aspnetmvc-version',
  'x-runtime',
  'x-version'
];

export interface ComponentVulnerability {
  component: string;
  version?: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  issue: string;
}

export function detectVulnerableComponents(event: VibeGuardEvent): ComponentVulnerability[] {
  const vulnerabilities: ComponentVulnerability[] = [];
  const headers = event.headers || {};

  for (const headerName of VULNERABLE_HEADERS) {
    const headerValue = headers[headerName] || headers[headerName.toLowerCase()] || headers[headerName.toUpperCase()];
    if (headerValue) {
      vulnerabilities.push({
        component: headerName,
        version: headerValue.toString(),
        risk: 'medium',
        issue: `Version information exposed in ${headerName} header`
      });
    }
  }

  if (event.payload && typeof event.payload === 'string') {
    const payload = event.payload.toLowerCase();

    for (const [component, versions] of Object.entries(KNOWN_VULNERABLE_VERSIONS)) {
      for (const version of versions) {
        if (payload.includes(component) && payload.includes(version)) {
          vulnerabilities.push({
            component,
            version,
            risk: 'high',
            issue: `Known vulnerable version of ${component} detected: ${version}`
          });
        }
      }
    }

    const versionPattern = /(jquery|react|angular|express|node)[\s:=\-]?v?(\d+\.\d+\.\d+)/gi;
    const matches = payload.matchAll(versionPattern);
    
    for (const match of matches) {
      const component = match[1].toLowerCase();
      const version = match[2];
      
      if (KNOWN_VULNERABLE_VERSIONS[component]?.includes(version)) {
        vulnerabilities.push({
          component,
          version,
          risk: 'high',
          issue: `Vulnerable version of ${component} detected: ${version}`
        });
      }
    }
  }

  if (event.url) {
    const url = event.url.toLowerCase();
    
    if (url.includes('/.git/') || url.includes('/.svn/') || url.includes('/.hg/')) {
      vulnerabilities.push({
        component: 'version-control',
        risk: 'critical',
        issue: 'Version control system exposed'
      });
    }

    if (url.includes('/package.json') || url.includes('/composer.json') || url.includes('/requirements.txt')) {
      vulnerabilities.push({
        component: 'dependencies',
        risk: 'high',
        issue: 'Dependency file exposed'
      });
    }
  }

  return vulnerabilities;
}

export function checkForCveReferences(event: VibeGuardEvent): string[] {
  const cves: string[] = [];
  
  if (event.payload && typeof event.payload === 'string') {
    const cvePattern = /CVE-\d{4}-\d{4,7}/gi;
    const matches = event.payload.matchAll(cvePattern);
    
    for (const match of matches) {
      cves.push(match[0].toUpperCase());
    }
  }

  return cves;
}

