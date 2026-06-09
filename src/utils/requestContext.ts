import { AsyncLocalStorage } from 'node:async_hooks';

/**
 * Kontekst bieżącego żądania HTTP propagowany przez AsyncLocalStorage.
 * Zastępuje dawne `(global as any).request`, które powodowało race condition
 * przy współbieżnych żądaniach.
 */
export interface RequestContext {
  ip?: string;
}

const requestContextStorage = new AsyncLocalStorage<RequestContext>();

/**
 * Uruchamia funkcję w kontekście danego żądania.
 * Wszystkie asynchroniczne kontynuacje (w tym wywołania fetch) widzą ten kontekst.
 * @param context - Kontekst żądania (np. IP klienta)
 * @param fn - Funkcja do uruchomienia w kontekście
 */
export function runWithRequestContext<T>(context: RequestContext, fn: () => T): T {
  return requestContextStorage.run(context, fn);
}

/**
 * Zwraca kontekst bieżącego żądania lub undefined poza kontekstem.
 */
export function getRequestContext(): RequestContext | undefined {
  return requestContextStorage.getStore();
}
