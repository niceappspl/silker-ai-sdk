import { RuntimeConfig } from '../types';

let runtimeConfig: RuntimeConfig = {
  debug: false,
  proxyMode: false,
  rateLimitThreshold: 5,
  slowRequestThreshold: 5000,
  enableAuditLogging: true,
  enablePerformanceMonitoring: true,
  customRules: []
};

let globalOptions: { debug?: boolean } | null = null;

/**
 * Ustawia globalne opcje dla modułu konfiguracji runtime.
 * @param options - Opcje konfiguracyjne z flagą debug
 */
export function setGlobalOptions(options: { debug?: boolean } | null) {
  globalOptions = options;
}

/**
 * Aktualizuje konfigurację runtime Silker.
 * @param updates - Częściowa konfiguracja do zaktualizowania
 * @returns Obiekt z flagą sukcesu i listą zaktualizowanych kluczy
 */
export function updateRuntimeConfig(updates: Partial<RuntimeConfig>): { success: boolean; updated: string[] } {
  const updated: string[] = [];

  Object.entries(updates).forEach(([key, value]) => {
    if (key in runtimeConfig) {
      (runtimeConfig as any)[key] = value;
      updated.push(key);

      if (key === 'debug' && globalOptions) {
        globalOptions.debug = value as boolean;
      }
    }
  });

  return { success: updated.length > 0, updated };
}

/**
 * Pobiera aktualną konfigurację runtime Silker.
 * @returns Kopia aktualnej konfiguracji runtime
 */
export function getRuntimeConfig(): RuntimeConfig {
  return { ...runtimeConfig };
}
