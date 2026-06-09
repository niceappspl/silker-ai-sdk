/**
 * `next/server` jest mockowany, dzięki czemu testy nie wymagają zainstalowanego Next.
 * Fałszywy `NextResponse` zwraca proste obiekty opisujące decyzję middleware.
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

function makeRequest(url: string, init?: RequestInit): Request {
  return new Request(url, init);
}

describe('nextMiddleware (Next.js Edge adapter)', () => {
  const middleware = nextMiddleware();

  it('blocks a SQLi payload in the URL query with a 403 json response', async () => {
    const req = makeRequest(
      "https://app.example.com/search?q=1' OR '1'='1' UNION SELECT password FROM users--",
    );
    const res = (await middleware(req)) as unknown as {
      __type: string;
      status: number;
      body: { error: string; type: string };
    };

    expect(res.__type).toBe('json');
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('Request blocked by Silker AI');
    expect(typeof res.body.type).toBe('string');
  });

  it('passes through a clean request', async () => {
    const req = makeRequest('https://app.example.com/about');
    const res = (await middleware(req)) as unknown as { __type: string; status: number };

    expect(res.__type).toBe('next');
    expect(res.status).toBe(200);
  });

  it('fails open (pass-through) and never throws on internal errors', async () => {
    // Brak/nieprawidłowy obiekt request nie może wysadzić aplikacji usera.
    const res = (await middleware({} as unknown as Request)) as unknown as { __type: string };
    expect(res.__type).toBe('next');
  });
});
