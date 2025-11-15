/**
 * Konfiguracja runtime Silker.
 */
export interface RuntimeConfig {
  /** Tryb debugowania */
  debug: boolean;
  /** Tryb proxy */
  proxyMode: boolean;
  /** Próg limitu szybkości (żądań na minutę) */
  rateLimitThreshold: number;
  /** Próg wolnego żądania w milisekundach */
  slowRequestThreshold: number;
  /** Włącza logowanie audytu */
  enableAuditLogging: boolean;
  /** Włącza monitorowanie wydajności */
  enablePerformanceMonitoring: boolean;
  /** Niestandardowe reguły bezpieczeństwa */
  customRules: any[];
}

/**
 * Status zdrowia systemu Silker.
 */
export interface HealthStatus {
  /** Ogólny status systemu */
  status: 'healthy' | 'degraded' | 'unhealthy';
  /** Znacznik czasu sprawdzenia */
  timestamp: number;
  /** Szczegóły poszczególnych sprawdzeń */
  checks: {
    /** Status pamięci */
    memory: { status: 'ok' | 'warning' | 'error'; usage: number };
    /** Status wydajności */
    performance: { status: 'ok' | 'warning' | 'error'; avgResponseTime: number };
    /** Status bezpieczeństwa */
    security: { status: 'ok' | 'warning' | 'error'; recentBlocks: number };
    /** Status łączności z chmurą */
    connectivity: { status: 'ok' | 'error'; lastCloudContact: number };
  };
  /** Czas działania w milisekundach */
  uptime: number;
  /** Wersja Silker */
  version: string;
}

