import { maybePrimeBansAndConfig, resetSyncStateForTests } from '../../src/cloud/sync';
import { isIpBanned, clearRateLimitState } from '../../src/detection/rateLimit';
import { SilkerOptions } from '../../src/types';

const flush = () => new Promise((r) => setTimeout(r, 25));

describe('pull-sync (maybePrimeBansAndConfig)', () => {
  const realFetch = global.fetch;

  beforeEach(() => {
    clearRateLimitState();
    resetSyncStateForTests();
  });

  afterEach(() => {
    global.fetch = realFetch;
  });

  it('is a no-op without an API key', async () => {
    let called = false;
    global.fetch = (async () => {
      called = true;
      return { ok: true, json: async () => ({ data: {} }) } as any;
    }) as any;

    maybePrimeBansAndConfig({} as SilkerOptions, true);
    await flush();
    expect(called).toBe(false);
  });

  it('primes the local ban list from the platform', async () => {
    const until = new Date(Date.now() + 60_000).toISOString();
    global.fetch = (async () => ({
      ok: true,
      json: async () => ({ data: { bannedIps: [{ ip: '9.9.9.9', until }], config: { features: {} } } }),
    })) as any;

    maybePrimeBansAndConfig({ apiKey: 'sk_test', appId: 'app1' } as SilkerOptions, true);
    await flush();
    expect(isIpBanned('9.9.9.9')).toBe(true);
  });

  it('respects the TTL (no refetch within the window)', async () => {
    let calls = 0;
    global.fetch = (async () => {
      calls++;
      return { ok: true, json: async () => ({ data: { bannedIps: [], config: { features: {} } } }) } as any;
    }) as any;

    maybePrimeBansAndConfig({ apiKey: 'sk_test' } as SilkerOptions, true);
    await flush();
    maybePrimeBansAndConfig({ apiKey: 'sk_test' } as SilkerOptions, false);
    await flush();
    expect(calls).toBe(1);
  });
});
