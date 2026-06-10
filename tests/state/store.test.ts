import { InMemoryStateStore, SilkerStateStore } from '../../src/state/store';
import { checkRateLimit, clearRateLimitState, setExternalStore, banIp, unbanIp, setRateLimitConfig } from '../../src/detection/rateLimit';
import { SilkerEvent } from '../../src/types';

describe('InMemoryStateStore', () => {
  it('increments a counter and applies the window TTL', async () => {
    const store = new InMemoryStateStore();
    expect(await store.incr('rate:1.2.3.4', 60000)).toBe(1);
    expect(await store.incr('rate:1.2.3.4', 60000)).toBe(2);
    expect(await store.get('rate:1.2.3.4')).toBe('2');
  });

  it('expires entries after the TTL', async () => {
    jest.useFakeTimers();
    const store = new InMemoryStateStore();
    await store.set('ban:1.2.3.4', 'x', 1000);
    expect(await store.get('ban:1.2.3.4')).toBe('x');
    jest.advanceTimersByTime(1500);
    expect(await store.get('ban:1.2.3.4')).toBeNull();
    jest.useRealTimers();
  });

  it('deletes keys', async () => {
    const store = new InMemoryStateStore();
    await store.set('k', 'v');
    await store.delete('k');
    expect(await store.get('k')).toBeNull();
  });
});

describe('rate limiting with an external store (best-effort mirroring)', () => {
  afterEach(() => {
    setExternalStore(null);
    clearRateLimitState();
    setRateLimitConfig({ windowMs: 60000, maxRequests: 300, banDurationMs: 300000 });
  });

  function makeEvent(ip: string): SilkerEvent {
    return { method: 'GET', url: '/api/x', ip, timestamp: Date.now() };
  }

  it('mirrors increments to the external store (fire-and-forget)', async () => {
    const store = new InMemoryStateStore();
    const incrSpy = jest.spyOn(store, 'incr');
    setExternalStore(store);

    expect(checkRateLimit(makeEvent('1.1.1.1'))).toBe(false);
    expect(checkRateLimit(makeEvent('1.1.1.1'))).toBe(false);

    // Mirror is async - allow the microtask queue to drain
    await new Promise(resolve => setImmediate(resolve));
    expect(incrSpy).toHaveBeenCalledTimes(2);
  });

  it('adopts a higher shared counter from the external store', async () => {
    setRateLimitConfig({ windowMs: 60000, maxRequests: 5 });
    const store = new InMemoryStateStore();
    // Simulate other instances having already consumed the shared budget
    const sharedStore: SilkerStateStore = {
      incr: async () => 100,
      get: async () => null,
      set: store.set.bind(store),
      delete: store.delete.bind(store),
    };
    setExternalStore(sharedStore);

    expect(checkRateLimit(makeEvent('2.2.2.2'), false)).toBe(false); // local count = 1
    await new Promise(resolve => setImmediate(resolve)); // pull shared count (100)
    expect(checkRateLimit(makeEvent('2.2.2.2'), false)).toBe(true); // 101 > 5
  });

  it('mirrors bans to the external store and removes them on unban', async () => {
    const store = new InMemoryStateStore();
    setExternalStore(store);

    banIp('3.3.3.3');
    await new Promise(resolve => setImmediate(resolve));
    expect(await store.get('silker:ban:3.3.3.3')).not.toBeNull();

    unbanIp('3.3.3.3');
    await new Promise(resolve => setImmediate(resolve));
    expect(await store.get('silker:ban:3.3.3.3')).toBeNull();
  });

  it('picks up a shared ban set by another instance (eventual consistency)', async () => {
    const store = new InMemoryStateStore();
    setExternalStore(store);
    await store.set('silker:ban:4.4.4.4', String(Date.now() + 60000), 60000);

    // First check triggers the async ban pull; the decision itself stays local
    checkRateLimit(makeEvent('4.4.4.4'));
    await new Promise(resolve => setImmediate(resolve));

    expect(checkRateLimit(makeEvent('4.4.4.4'))).toBe(true);
  });
});
