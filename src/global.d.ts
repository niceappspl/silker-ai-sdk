import { EventEmitter } from 'events';

/**
 * Deklaracje globalnych zmiennych używanych przez Silker.
 * @global
 */
declare global {
  /** Globalna funkcja fetch do przechwytywania */
  var fetch: typeof fetch;
  /** Emiter zdarzeń Silker */
  var silkerEmitter: EventEmitter;
  /** Czas startu Silker */
  var silkerStartTime: number;
  /** Ostatni kontakt z chmurą */
  var lastCloudContact: number;
}

export {};
