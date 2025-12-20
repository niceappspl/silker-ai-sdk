import nock from 'nock';
import { hookFetch, resetFetchHook } from '../../src/hooks/fetch';
import { SilkerOptions } from '../../src/types';
import { clearRateLimitState } from '../../src/detection/rateLimit';
import { setGlobalOptions } from '../../src/detection/anomaly';

describe('hookFetch', () => {
  const mockOptions: SilkerOptions = {
    apiKey: 'sk_test1234567890abcdefghijklmnopqrstuvwxyz123456789',
    endpoint: 'https://test-silker.com/api',
    debug: false,
    features: {
      sqliDetection: true,
      xssDetection: true,
      pathTraversalDetection: true,
      rateLimit: false,
      csrfDetection: false,
      ssrfDetection: false,
      idorDetection: false,
      hostHeaderInjectionDetection: false,
      accessControlDetection: false,
      cryptographicValidation: false,
      vulnerableComponentsDetection: false,
      authenticationValidation: false,
      softwareIntegrityValidation: false,
      securityHeadersValidation: false,
      dataLeakageDetection: false,
      apiSchemaValidation: false,
      sessionAnomaliesDetection: false,
      fileUploadDetection: false,
      thirdPartyDetection: false,
      complianceDetection: false,
      threatIntelligence: false,
      zeroTrustDetection: false,
      promptInjectionDetection: false
    }
  };

  let originalFetch: typeof global.fetch;
  let mockFetch: jest.Mock;

  beforeEach(() => {
    resetFetchHook();
    clearRateLimitState();
    setGlobalOptions(null);
    delete (global as any).request;
    originalFetch = global.fetch;
    nock.cleanAll();
    nock.disableNetConnect();
    
    mockFetch = jest.fn().mockImplementation((url: string, init?: RequestInit) => {
      return Promise.resolve(new Response(JSON.stringify({ data: [] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      }));
    });
    
    global.fetch = mockFetch as any;
  });

  afterEach(() => {
    global.fetch = originalFetch;
    nock.cleanAll();
    nock.disableNetConnect();
  });

  it('should intercept fetch calls', () => {
    hookFetch(mockOptions);
    expect(global.fetch).not.toBe(originalFetch);
  });

  it('should allow legitimate fetch requests', async () => {
    nock('https://test-silker.com')
      .post('/api')
      .reply(200, { block: false });

    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({ data: [] }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    }));

    hookFetch(mockOptions);

    const response = await global.fetch('https://api.example.com/users', {
      headers: { 'Authorization': 'Bearer token' }
    });
    expect(response.status).toBe(200);
    const data = await response.json();
    expect(data.data).toEqual([]);
  });

  it('should block requests with SQL injection', async () => {
    nock('https://test-silker.com')
      .post('/api')
      .reply(200, { block: true, alertId: 'alert-123' });

    hookFetch(mockOptions);

    const response = await global.fetch('https://api.example.com/search', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer token' },
      body: JSON.stringify({ query: "'; DROP TABLE users; --" })
    });

    expect(response.status).toBe(403);
    const data = await response.json();
    expect(data.error).toBe('Request blocked by Silker AI');
  });

  it('should block requests with XSS', async () => {
    nock('https://test-silker.com')
      .post('/api')
      .reply(200, { block: true, alertId: 'alert-xss' });

    hookFetch(mockOptions);

    const response = await global.fetch('https://api.example.com/comment', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer token' },
      body: JSON.stringify({ content: '<script>alert("xss")</script>' })
    });

    expect(response.status).toBe(403);
  });

  it('should handle cloud connection failure gracefully for safe requests', async () => {
    nock('https://test-silker.com')
      .post('/api')
      .reply(500);

    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({ data: [] }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    }));

    hookFetch(mockOptions);

    const response = await global.fetch('https://api.example.com/users', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer token' },
      body: JSON.stringify({ query: "safe query" })
    });

    expect(response.status).toBe(200);
  });

  it('should preserve original fetch behavior for non-anomalous requests', async () => {
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({ data: [] }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    }));

    hookFetch(mockOptions);

    const response = await global.fetch('https://api.example.com/users', {
      headers: { 'Authorization': 'Bearer token' }
    });
    const data = await response.json();
    expect(data.data).toEqual([]);
  });

  it('should handle fetch with Request object', async () => {
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({ data: [] }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    }));

    hookFetch(mockOptions);

    const request = new Request('https://api.example.com/users', {
      headers: { 'Authorization': 'Bearer token' }
    });
    const response = await global.fetch(request);
    expect(response.status).toBe(200);
  });

  it('should handle fetch with URL object', async () => {
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({ data: [] }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    }));

    hookFetch(mockOptions);

    const url = new URL('https://api.example.com/users');
    const response = await global.fetch(url, {
      headers: { 'Authorization': 'Bearer token' }
    });
    expect(response.status).toBe(200);
  });

  it('should pass through headers and init options', async () => {
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    }));

    hookFetch(mockOptions);

    const response = await global.fetch('https://api.example.com/users', {
      method: 'POST',
      headers: {
        'authorization': 'Bearer token123',
        'content-type': 'application/json'
      },
      body: JSON.stringify({ name: 'John' })
    });

    expect(response.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledWith(
      'https://api.example.com/users',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'authorization': 'Bearer token123',
          'content-type': 'application/json'
        })
      })
    );
  });
});
