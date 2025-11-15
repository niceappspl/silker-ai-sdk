import { PerformanceMetrics } from '../types';

const performanceHistory: PerformanceMetrics[] = [];
const PERFORMANCE_WINDOW = 100;
const SLOW_REQUEST_THRESHOLD = 5000;

/**
 * Zapisuje metryki wydajności żądania.
 * @param event - Zdarzenie Silker
 * @param responseTime - Czas odpowiedzi w milisekundach
 * @param statusCode - Opcjonalny kod statusu HTTP
 */
export function recordPerformanceMetrics(event: import('../types').SilkerEvent, responseTime: number, statusCode?: number): void {
  const metrics: PerformanceMetrics = {
    endpoint: event.url,
    method: event.method,
    responseTime,
    timestamp: Date.now(),
    ip: event.ip || 'unknown',
    statusCode
  };

  performanceHistory.push(metrics);

  if (performanceHistory.length > PERFORMANCE_WINDOW) {
    performanceHistory.shift();
  }
}

/**
 * Wykrywa anomalie wydajności na podstawie historii metryk.
 * Analizuje średni czas odpowiedzi, wolne żądania i wolne endpointy.
 * @returns Obiekt z listą anomalii, średnim czasem odpowiedzi i liczbą wolnych żądań
 */
export function detectPerformanceAnomalies(): { anomalies: string[]; averageResponseTime: number; slowRequests: number } {
  if (performanceHistory.length < 10) {
    return { anomalies: [], averageResponseTime: 0, slowRequests: 0 };
  }

  const anomalies: string[] = [];
  const recentMetrics = performanceHistory.slice(-50);

  const totalTime = recentMetrics.reduce((sum, metric) => sum + metric.responseTime, 0);
  const averageResponseTime = totalTime / recentMetrics.length;

  const slowRequests = recentMetrics.filter(metric => metric.responseTime > SLOW_REQUEST_THRESHOLD).length;

  if (averageResponseTime > 2000) {
    anomalies.push(`High average response time: ${averageResponseTime.toFixed(2)}ms`);
  }

  if (slowRequests > recentMetrics.length * 0.3) {
    anomalies.push(`High number of slow requests: ${slowRequests}/${recentMetrics.length}`);
  }

  const endpointMetrics = new Map<string, number[]>();
  recentMetrics.forEach(metric => {
    if (!endpointMetrics.has(metric.endpoint)) {
      endpointMetrics.set(metric.endpoint, []);
    }
    endpointMetrics.get(metric.endpoint)!.push(metric.responseTime);
  });

  endpointMetrics.forEach((times, endpoint) => {
    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    if (avg > 3000) {
      anomalies.push(`Slow endpoint detected: ${endpoint} (${avg.toFixed(2)}ms average)`);
    }
  });

  return { anomalies, averageResponseTime, slowRequests };
}

/**
 * Generuje raport wydajności zawierający podsumowanie, ostatnie metryki i wykryte anomalie.
 * @returns Raport wydajności z podsumowaniem, ostatnimi metrykami i listą anomalii
 */
export function getPerformanceReport(): {
  summary: any;
  recentMetrics: PerformanceMetrics[];
  anomalies: string[];
} {
  const { anomalies, averageResponseTime, slowRequests } = detectPerformanceAnomalies();

  return {
    summary: {
      totalRequests: performanceHistory.length,
      averageResponseTime: Math.round(averageResponseTime),
      slowRequests,
      timeRange: performanceHistory.length > 0 ?
        `${performanceHistory[0].timestamp} - ${performanceHistory[performanceHistory.length - 1].timestamp}` :
        'No data'
    },
    recentMetrics: performanceHistory.slice(-20),
    anomalies
  };
}

