import { EventEmitter } from 'events';

const SILKER_NAMESPACE = Symbol.for('silker-ai-internal');

export interface SilkerGlobalState {
  startTime: number;
  emitter: EventEmitter | null;
  lastCloudContact: number;
}

/**
 * Bezpieczny dostęp do globalnego stanu Silker AI.
 * Używa Symbol namespace aby uniknąć kolizji z innymi bibliotekami.
 */
export function getSilkerState(): SilkerGlobalState {
  if (!(global as any)[SILKER_NAMESPACE]) {
    (global as any)[SILKER_NAMESPACE] = {
      startTime: 0,
      emitter: null,
      lastCloudContact: 0
    };
  }
  return (global as any)[SILKER_NAMESPACE];
}

