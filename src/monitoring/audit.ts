import { SilkerEvent } from '../types';
import { AuditLogEntry } from '../types/metrics';
import { createLogger } from '../utils/logger';

const auditLogs: AuditLogEntry[] = [];
const MAX_AUDIT_LOGS = 10000;

let globalOptions: { debug?: boolean } | null = null;

/**
 * Ustawia globalne opcje dla modułu audytu.
 * @param options - Opcje konfiguracyjne z flagą debug
 */
export function setGlobalOptions(options: { debug?: boolean } | null) {
  globalOptions = options;
}

/**
 * Loguje zdarzenie audytu do dziennika.
 * @param event - Zdarzenie Silker do zalogowania
 * @param action - Akcja wykonana na żądaniu
 * @param reason - Powód akcji
 * @param severity - Poziom ważności (domyślnie: 'low')
 * @param metadata - Opcjonalne dodatkowe metadane
 */
export function logAuditEvent(
  event: SilkerEvent,
  action: 'allowed' | 'blocked' | 'flagged',
  reason: string,
  severity: 'low' | 'medium' | 'high' | 'critical' = 'low',
  metadata?: any
): void {
  const auditEntry: AuditLogEntry = {
    id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    timestamp: Date.now(),
    event: { ...event },
    action,
    reason,
    severity,
    metadata
  };

  auditLogs.push(auditEntry);

  if (auditLogs.length > MAX_AUDIT_LOGS) {
    auditLogs.shift();
  }

  if (globalOptions?.debug) {
    const logger = createLogger(globalOptions as any);
    logger.debug(`AUDIT [${severity.toUpperCase()}]: ${action} - ${reason}`);
  }
}

/**
 * Pobiera wpisy z dziennika audytu z opcjonalnymi filtrami.
 * @param limit - Maksymalna liczba wpisów do zwrócenia (domyślnie: 100)
 * @param severity - Opcjonalny filtr poziomu ważności
 * @param action - Opcjonalny filtr akcji
 * @returns Tablica wpisów audytu
 */
export function getAuditLogs(
  limit: number = 100,
  severity?: 'low' | 'medium' | 'high' | 'critical',
  action?: 'allowed' | 'blocked' | 'flagged'
): AuditLogEntry[] {
  let filteredLogs = auditLogs;

  if (severity) {
    filteredLogs = filteredLogs.filter(log => log.severity === severity);
  }

  if (action) {
    filteredLogs = filteredLogs.filter(log => log.action === action);
  }

  return filteredLogs.slice(-limit);
}

/**
 * Generuje podsumowanie dziennika audytu.
 * @returns Podsumowanie z całkowitą liczbą wpisów, podziałem według ważności i akcji oraz ostatnią aktywnością
 */
export function getAuditSummary(): {
  totalLogs: number;
  severityBreakdown: Record<string, number>;
  actionBreakdown: Record<string, number>;
  recentActivity: AuditLogEntry[];
} {
  const severityBreakdown: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 };
  const actionBreakdown: Record<string, number> = { allowed: 0, blocked: 0, flagged: 0 };

  auditLogs.forEach(log => {
    severityBreakdown[log.severity]++;
    actionBreakdown[log.action]++;
  });

  return {
    totalLogs: auditLogs.length,
    severityBreakdown,
    actionBreakdown,
    recentActivity: auditLogs.slice(-10)
  };
}

export function clearAuditLogs(): void {
  auditLogs.length = 0;
}

