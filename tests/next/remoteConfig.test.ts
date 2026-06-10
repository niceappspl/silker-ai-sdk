/**
 * Testy aplikowania remote config (features z dashboardu) i banów z odpowiedzi
 * ingestu w adapterze Edge (parytet z node telemetry). Osobny plik — świeży
 * rejestr modułów (flaga `configured` w src/next jest per proces).
 */
jest.mock(
  'next/server',
  () => ({
    NextResponse: {
      next: () => ({ __type: 'next', status: 200 }),
      json: (body: unknown, init?: { status?: number }) => ({
        __type: 'json',
        status: init?.status ?? 200,
        body,
      }),
    },
  }),
  { virtual: true },
);

import { nextMiddleware } from '../../src/next';
import { setGlobalOptions } from '../../src/detection/anomaly';
import { clearRateLimitState } from '../../src/detection/rateLimit';

const SQLI_URL = "https://app.example.com/search?q=1' OR '1'='1' UNION SELECT password FROM users--";

function mockIngestFetch(data: unknown): jest.Mock {
  return jest.fn().mockResolvedValue({
    json: async () => ({ data }),
  });
}

async function drainAsync(): Promise<void> {
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));
}

describe('nextMiddleware remote config (ingest response)', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    clearRateLimitState();
    // Reset detection state to defaults — applyRemoteFeatures mutates global options.
    setGlobalOptions({ features: {} });
  });

  afterEach(() => {
    global.fetch = originalFetch;
    setGlobalOptions(null);
    clearRateLimitState();
  });

  it('applies dashboard features from the ingest response (default remoteConfig)', async () => {
    global.fetch = mockIngestFetch({ config: { features: { sqliDetection: false } } }) as any;
    const middleware = nextMiddleware({ apiKey: 'sk_test_remote_config_key_1234567890123456' });

    // Clean request triggers telemetry; the response carries the remote config.
    const first = (await middleware(new Request('https://app.example.com/about'))) as any;
    expect(first.__type).toBe('next');
    await drainAsync();

    // sqliDetection disabled remotely — the SQLi payload must now pass through.
    const second = (await middleware(new Request(SQLI_URL))) as any;
    expect(second.__type).toBe('next');
  });

  it('does NOT apply dashboard features when remoteConfig: false', async () => {
    global.fetch = mockIngestFetch({ config: { features: { sqliDetection: false } } }) as any;
    const middleware = nextMiddleware({
      apiKey: 'sk_test_remote_config_key_1234567890123456',
      remoteConfig: false,
    });

    const first = (await middleware(new Request('https://app.example.com/about'))) as any;
    expect(first.__type).toBe('next');
    await drainAsync();

    // Remote config ignored — SQLi stays blocked.
    const second = (await middleware(new Request(SQLI_URL))) as any;
    expect(second.__type).toBe('json');
    expect(second.status).toBe(403);
  });

  it('syncs banned IPs from the ingest response', async () => {
    global.fetch = mockIngestFetch({
      bannedIps: [{ ip: '203.0.113.66', until: new Date(Date.now() + 60000).toISOString() }],
    }) as any;
    const middleware = nextMiddleware({ apiKey: 'sk_test_remote_config_key_1234567890123456' });

    const first = (await middleware(new Request('https://app.example.com/about'))) as any;
    expect(first.__type).toBe('next');
    await drainAsync();

    const banned = (await middleware(
      new Request('https://app.example.com/about', { headers: { 'x-real-ip': '203.0.113.66' } }),
    )) as any;
    expect(banned.__type).toBe('json');
    expect(banned.status).toBe(403);
  });
});
