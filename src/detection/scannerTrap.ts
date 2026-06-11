/**
 * Scanner trap (honeypot paths) - aktywna obrona przed automatycznymi skanerami.
 *
 * Aplikacje Node/Next NIGDY nie serwują legalnie ścieżek typu /.env, /wp-login.php
 * czy /.git/config - żądanie do nich to niemal pewny sygnał skanera/bota exploitującego
 * (praktycznie zerowy false positive rate). Trafienie w pułapkę pozwala zbanować IP
 * ZANIM atakujący znajdzie realną podatność.
 */

export interface ScannerTrapResult {
  detected: boolean;
  /** Dopasowana ścieżka-pułapka (do opisu zagrożenia) */
  matchedPath?: string;
  /** Kategoria sygnału (env-probe / cms-probe / vcs-probe / admin-probe / backup-probe) */
  category?: string;
}

/**
 * Ścieżki-pułapki: dopasowanie po PREFIKSIE pathname (lowercase, bez query stringa).
 * Tylko ścieżki, których aplikacja Node/Next nie wystawia legalnie.
 * Świadomie pominięte: /.well-known (legalne ACME/security.txt), /admin (częsty legalny panel).
 */
const TRAP_PREFIXES: { prefix: string; category: string }[] = [
  // Pliki środowiskowe / sekrety
  { prefix: '/.env', category: 'env-probe' },
  { prefix: '/.aws/', category: 'env-probe' },
  { prefix: '/.ssh/', category: 'env-probe' },
  { prefix: '/.npmrc', category: 'env-probe' },
  { prefix: '/.htpasswd', category: 'env-probe' },
  { prefix: '/.htaccess', category: 'env-probe' },
  // Repozytoria / IDE
  { prefix: '/.git/', category: 'vcs-probe' },
  { prefix: '/.svn/', category: 'vcs-probe' },
  { prefix: '/.hg/', category: 'vcs-probe' },
  { prefix: '/.vscode/', category: 'vcs-probe' },
  { prefix: '/.idea/', category: 'vcs-probe' },
  // CMS / PHP (czysty sygnał skanera na stacku Node)
  { prefix: '/wp-admin', category: 'cms-probe' },
  { prefix: '/wp-login.php', category: 'cms-probe' },
  { prefix: '/wp-content/', category: 'cms-probe' },
  { prefix: '/wp-includes/', category: 'cms-probe' },
  { prefix: '/xmlrpc.php', category: 'cms-probe' },
  { prefix: '/wordpress/', category: 'cms-probe' },
  // Panele administracyjne / narzędzia
  { prefix: '/phpmyadmin', category: 'admin-probe' },
  { prefix: '/pma/', category: 'admin-probe' },
  { prefix: '/adminer', category: 'admin-probe' },
  { prefix: '/phpinfo', category: 'admin-probe' },
  { prefix: '/cgi-bin/', category: 'admin-probe' },
  { prefix: '/actuator/', category: 'admin-probe' },
  { prefix: '/solr/', category: 'admin-probe' },
  { prefix: '/jenkins/', category: 'admin-probe' },
  { prefix: '/manager/html', category: 'admin-probe' },
  { prefix: '/_profiler/', category: 'admin-probe' },
  { prefix: '/telescope/', category: 'admin-probe' },
  // Backupy / dumpy
  { prefix: '/backup.sql', category: 'backup-probe' },
  { prefix: '/dump.sql', category: 'backup-probe' },
  { prefix: '/db.sql', category: 'backup-probe' },
  { prefix: '/database.sql', category: 'backup-probe' },
  { prefix: '/backup.zip', category: 'backup-probe' },
  { prefix: '/backup.tar', category: 'backup-probe' },
  { prefix: '/www.zip', category: 'backup-probe' },
  { prefix: '/site.zip', category: 'backup-probe' },
];

/** Sufiksy plikowe sygnalizujące skan (gdziekolwiek w drzewie, np. /api/../config.php) */
const TRAP_SUFFIXES: { suffix: string; category: string }[] = [
  { suffix: '/shell.php', category: 'cms-probe' },
  { suffix: '/config.php', category: 'cms-probe' },
  { suffix: '/info.php', category: 'admin-probe' },
  { suffix: '/.env', category: 'env-probe' },
  { suffix: '/web.config', category: 'env-probe' },
];

/**
 * Wyciąga pathname z surowego URL-a zdarzenia (obsługuje pełne URL-e i same ścieżki).
 */
function extractPathname(url: string): string {
  try {
    if (url.startsWith('http://') || url.startsWith('https://')) {
      return new URL(url).pathname;
    }
  } catch {
    // fall through - traktuj jako ścieżkę
  }
  const queryIndex = url.indexOf('?');
  return queryIndex === -1 ? url : url.substring(0, queryIndex);
}

/**
 * Sprawdza czy żądanie trafia w ścieżkę-pułapkę znaną ze skanerów/exploitów.
 * @param url - URL żądania (pełny lub sam pathname)
 */
export function detectScannerTrap(url: string): ScannerTrapResult {
  if (!url) return { detected: false };

  const pathname = extractPathname(url).toLowerCase();

  for (const { prefix, category } of TRAP_PREFIXES) {
    if (pathname.startsWith(prefix)) {
      return { detected: true, matchedPath: prefix, category };
    }
  }

  for (const { suffix, category } of TRAP_SUFFIXES) {
    if (pathname.endsWith(suffix)) {
      return { detected: true, matchedPath: suffix, category };
    }
  }

  return { detected: false };
}
