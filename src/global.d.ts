import { EventEmitter } from 'events';

/**
 * Deklaracje globalnych zmiennych używanych przez VibeGuard.
 * @global
 */
declare global {
  /** Globalna funkcja fetch do przechwytywania */
  var fetch: typeof fetch;
  /** Obiekt żądania Express */
  var request: any;
  /** Emiter zdarzeń VibeGuard */
  var vibeGuardEmitter: EventEmitter;
  /** Obiekt żądania (alternatywny) */
  var req: any;
  /** Obiekt połączenia */
  var connection: any;
  /** Adres zdalny */
  var remoteAddress: string;
  /** Czas startu VibeGuard */
  var vibeGuardStartTime: number;
  /** Ostatni kontakt z chmurą */
  var lastCloudContact: number;
}

export {};
