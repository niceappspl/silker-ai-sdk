/**
 * Opcje konfiguracyjne dla VibeGuard.
 */
export interface VibeGuardOptions {
  /** Klucz API wymagany do komunikacji z chmurą */
  apiKey: string;
  /** Opcjonalny endpoint chmury (domyślnie: https://vibeguard.cloudflareworkers.com/api) */
  endpoint?: string;
  /** Włącza tryb debugowania z dodatkowymi logami */
  debug?: boolean;
  /** Włącza tryb proxy HTTP */
  proxyMode?: boolean;
}

