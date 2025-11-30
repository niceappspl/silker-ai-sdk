import { SilkerEvent } from '../types';
import { UserSession } from '../types/sessions';

const userSessions = new Map<string, UserSession>();
const BEHAVIOR_ANALYSIS_WINDOW = 5 * 60 * 1000;

let globalOptions: { debug?: boolean } | null = null;

/**
 * Ustawia globalne opcje dla modułu analizy zachowania użytkownika.
 * @param options - Opcje konfiguracyjne z flagą debug
 */
export function setGlobalOptions(options: { debug?: boolean } | null) {
  globalOptions = options;
}

/**
 * Generuje klucz sesji użytkownika na podstawie IP i User-Agent.
 * @param ip - Adres IP użytkownika
 * @param userAgent - User-Agent użytkownika
 * @returns Klucz sesji
 */
function getUserKey(ip: string, userAgent: string): string {
  return `${ip}:${userAgent?.substring(0, 50) || 'unknown'}`;
}

/**
 * Analizuje zachowanie użytkownika pod kątem anomalii.
 * Sprawdza wzorce żądań, odstępy czasowe, wykrywanie botów i podejrzane kombinacje metod HTTP.
 * @param event - Zdarzenie do analizy
 * @returns Obiekt z flagą anomalii, wynikiem punktowym i listą powodów
 */
export function analyzeUserBehavior(event: SilkerEvent): { isAnomalous: boolean; score: number; reasons: string[] } {
  const reasons: string[] = [];
  let anomalyScore = 0;

  const userKey = getUserKey(event.ip || 'unknown', event.userAgent || 'unknown');
  const now = event.timestamp || Date.now();

  let session = userSessions.get(userKey);

  if (!session) {
    session = {
      ip: event.ip || 'unknown',
      userAgent: event.userAgent || 'unknown',
      startTime: now,
      lastActivity: now,
      requestCount: 1,
      endpoints: new Set([event.url]),
      methods: new Set([event.method]),
      timeBetweenRequests: [],
      averageRequestInterval: 0,
      isBot: false,
      anomalyScore: 0
    };
    userSessions.set(userKey, session);
  } else {
    const timeDiff = now - session.lastActivity;
    session.timeBetweenRequests.push(timeDiff);

    if (session.timeBetweenRequests.length > 20) {
      session.timeBetweenRequests = session.timeBetweenRequests.slice(-20);
    }

    session.averageRequestInterval = session.timeBetweenRequests.reduce((a, b) => a + b, 0) / session.timeBetweenRequests.length;

    session.lastActivity = now;
    session.requestCount++;
    session.endpoints.add(event.url);
    session.methods.add(event.method);
  }

  // Check for long session with few requests BEFORE calculating anomaly score
  const sessionDuration = now - session.startTime;
  if (sessionDuration > 30 * 60 * 1000 && session.requestCount < 5) {
    anomalyScore += 10;
    reasons.push('Long session with few requests');
  }

  const recentIntervals = session.timeBetweenRequests.slice(-10);

  if (recentIntervals.length >= 5) {
    const avgInterval = recentIntervals.reduce((a, b) => a + b, 0) / recentIntervals.length;
    const variance = recentIntervals.reduce((sum, interval) => sum + Math.pow(interval - avgInterval, 2), 0) / recentIntervals.length;
    const stdDev = Math.sqrt(variance);

    if (stdDev < 100 && avgInterval < 1000) {
      session.isBot = true;
      anomalyScore += 30;
      reasons.push('Highly regular request intervals (bot-like)');
    }
  }

  if (session.endpoints.size > 10 && session.requestCount < 20) {
    anomalyScore += 20;
    reasons.push('Accessing too many endpoints too quickly');
  }

  if (recentIntervals.length >= 3) {
    const veryFastRequests = recentIntervals.filter(interval => interval < 200).length;
    if (veryFastRequests >= 3) {
      anomalyScore += 25;
      reasons.push('Multiple very fast consecutive requests');
    }
  }

  const suspiciousMethodCombos = [
    ['DELETE', 'PUT', 'PATCH'],
    ['OPTIONS', 'TRACE', 'CONNECT']
  ];

  for (const combo of suspiciousMethodCombos) {
    if (combo.every(method => session.methods.has(method))) {
      anomalyScore += 15;
      reasons.push(`Suspicious method combination: ${combo.join(', ')}`);
    }
  }

  const apiRequests = Array.from(session.endpoints).filter(url => url.includes('/api/')).length;
  if (apiRequests > session.endpoints.size * 0.8 && session.requestCount > 50) {
    anomalyScore += 15;
    reasons.push('Excessive API endpoint access');
  }

  session.anomalyScore = anomalyScore;

  for (const [key, sess] of userSessions.entries()) {
    if (now - sess.lastActivity > BEHAVIOR_ANALYSIS_WINDOW) {
      userSessions.delete(key);
    }
  }

  const isAnomalous = anomalyScore > 50;

  return { isAnomalous, score: anomalyScore, reasons };
}

export function resetUserSessions() {
  userSessions.clear();
}

import { createLogger } from '../utils/logger';

/**
 * Wykrywa anomalie w sesji użytkownika.
 * @param event - Zdarzenie do sprawdzenia
 * @returns true jeśli wykryto anomalie w sesji, false w przeciwnym razie
 */
export function detectSessionAnomalies(event: SilkerEvent): boolean {
  const behavior = analyzeUserBehavior(event);

  if (behavior.isAnomalous) {
    if (globalOptions?.debug) {
      const logger = createLogger(globalOptions as any); // Cast as it expects full SilkerOptions but only needs debug
      logger.debug('🚨 User behavior anomaly detected:', {
        score: behavior.score,
        reasons: behavior.reasons,
        ip: event.ip,
        userAgent: event.userAgent?.substring(0, 50)
      });
    }
    return true;
  }

  return false;
}

