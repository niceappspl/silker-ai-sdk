/**
 * Pluggable rozproszony magazyn stanu dla rate limitingu i banów IP.
 *
 * Lokalne Mapy w procesie pozostają AUTORYTATYWNE dla synchronicznej decyzji
 * block/allow (isAnomaly jest sync — nie może czekać na sieć). Zewnętrzny
 * store (np. Redis) jest lustrzany best-effort: inkrementy są dosyłane
 * fire-and-forget, a współdzielone liczniki/bany są okresowo zaciągane.
 * Konsekwencja: stan między instancjami jest EVENTUALLY consistent —
 * pojedyncza instancja może chwilowo przepuścić ruch ponad wspólny limit.
 */

/** Interfejs adaptera magazynu stanu (np. Redis). Wszystkie metody async. */
export interface SilkerStateStore {
  /**
   * Atomowo inkrementuje licznik pod kluczem i zwraca nową wartość.
   * Przy pierwszym inkremencie w oknie implementacja powinna ustawić TTL = windowMs.
   */
  incr(key: string, windowMs: number): Promise<number>;
  /** Zwraca wartość klucza lub null gdy brak/wygasł. */
  get(key: string): Promise<string | null>;
  /** Ustawia wartość z opcjonalnym TTL w ms. */
  set(key: string, value: string, ttlMs?: number): Promise<void>;
  /** Usuwa klucz. */
  delete(key: string): Promise<void>;
}

interface StoredEntry {
  value: string;
  count: number;
  expiresAt: number | null;
}

/**
 * Domyślna implementacja in-memory zgodna z SilkerStateStore.
 * Odpowiada semantyce wewnętrznych Map rate limitera (licznik per okno + TTL).
 */
export class InMemoryStateStore implements SilkerStateStore {
  private entries = new Map<string, StoredEntry>();

  private getLive(key: string): StoredEntry | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt !== null && entry.expiresAt <= Date.now()) {
      this.entries.delete(key);
      return undefined;
    }
    return entry;
  }

  async incr(key: string, windowMs: number): Promise<number> {
    const existing = this.getLive(key);
    if (existing) {
      existing.count += 1;
      existing.value = String(existing.count);
      return existing.count;
    }
    this.entries.set(key, { value: '1', count: 1, expiresAt: Date.now() + windowMs });
    return 1;
  }

  async get(key: string): Promise<string | null> {
    return this.getLive(key)?.value ?? null;
  }

  async set(key: string, value: string, ttlMs?: number): Promise<void> {
    const numeric = Number(value);
    this.entries.set(key, {
      value,
      count: Number.isFinite(numeric) ? numeric : 0,
      expiresAt: ttlMs ? Date.now() + ttlMs : null,
    });
  }

  async delete(key: string): Promise<void> {
    this.entries.delete(key);
  }
}
