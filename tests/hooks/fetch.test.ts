import nock from 'nock';
import { hookFetch, resetFetchHook } from '../../src/hooks/fetch';
import { SilkerOptions } from '../../src/types';
import { clearRateLimitState } from '../../src/detection/rateLimit';
import { setGlobalOptions } from '../../src/detection/anomaly';
import { runWithRequestContext } from '../../src/utils/requestContext';
import * as dashboard from '../../src/cloud/dashboard';

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
      promptInjectionDetection: false,
      ipBanning: true
    }
  };

  let originalFetch: typeof global.fetch;
  let mockFetch: jest.Mock;

  beforeEach(() => {
    resetFetchHook();
    clearRateLimitState();
    setGlobalOptions(null);
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

  it('should block requests with SQL injection when blockOutgoing is enabled', async () => {
    nock('https://test-silker.com')
      .post('/api')
      .reply(200, { block: true, alertId: 'alert-123' });

    hookFetch({ ...mockOptions, blockOutgoing: true });

    const response = await global.fetch('https://api.example.com/search', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer token' },
      body: JSON.stringify({ query: "'; DROP TABLE users; --" })
    });

    expect(response.status).toBe(403);
    const data = await response.json();
    expect(data.error).toBe('Request blocked by Silker AI');
  });

  it('should BYPASS internal SDK requests (x-silker-client-version) without analysis', async () => {
    const threatSpy = jest.spyOn(dashboard, 'sendThreatToDashboard').mockResolvedValue();

    // blockOutgoing ON + anomalous body would normally be blocked (403).
    hookFetch({ ...mockOptions, blockOutgoing: true });

    const response = await global.fetch('https://platform.silkerai.com/api/sync', {
      method: 'POST',
      headers: { 'x-silker-client-version': '1.6.0' },
      body: JSON.stringify({ query: "'; DROP TABLE users; --" })
    });

    // Internal request is passed straight through to the original fetch (mock).
    expect(response.status).toBe(200);
    expect(mockFetch).toHaveBeenCalled();
    expect(threatSpy).not.toHaveBeenCalled();

    threatSpy.mockRestore();
  });

  it('should block requests with XSS when blockOutgoing is enabled', async () => {
    nock('https://test-silker.com')
      .post('/api')
      .reply(200, { block: true, alertId: 'alert-xss' });

    hookFetch({ ...mockOptions, blockOutgoing: true });

    const response = await global.fetch('https://api.example.com/comment', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer token' },
      body: JSON.stringify({ content: '<script>alert("xss")</script>' })
    });

    expect(response.status).toBe(403);
  });

  it('should NOT block anomalous outgoing requests by default (monitor-only)', async () => {
    const threatSpy = jest.spyOn(dashboard, 'sendThreatToDashboard').mockResolvedValue();

    hookFetch(mockOptions);

    const response = await global.fetch('https://api.example.com/search', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer token' },
      body: JSON.stringify({ query: "'; DROP TABLE users; --" })
    });

    expect(response.status).toBe(200);
    expect(mockFetch).toHaveBeenCalled();
    expect(threatSpy).toHaveBeenCalled();
    expect(threatSpy.mock.calls[0][3]).toBe(false); // blocked = false

    threatSpy.mockRestore();
  });

  it('should detect SSRF on outgoing requests and report it (monitor-only by default)', async () => {
    const threatSpy = jest.spyOn(dashboard, 'sendThreatToDashboard').mockResolvedValue();

    // ssrfDetection not explicitly set - outboundSsrfProtection defaults to TRUE
    hookFetch({ ...mockOptions, features: { ...mockOptions.features, ssrfDetection: undefined } });

    const response = await global.fetch('http://169.254.169.254/latest/meta-data', {
      headers: { 'Authorization': 'Bearer token' }
    });

    expect(response.status).toBe(200);
    expect(mockFetch).toHaveBeenCalled();
    expect(threatSpy).toHaveBeenCalled();

    threatSpy.mockRestore();
  });

  it('should NOT run outbound SSRF check when ssrfDetection is explicitly false (backward compat)', async () => {
    const threatSpy = jest.spyOn(dashboard, 'sendThreatToDashboard').mockResolvedValue();

    // mockOptions has ssrfDetection: false - explicit user intent disables outbound too
    hookFetch(mockOptions);

    const response = await global.fetch('http://169.254.169.254/latest/meta-data', {
      headers: { 'Authorization': 'Bearer token' }
    });

    expect(response.status).toBe(200);
    expect(threatSpy).not.toHaveBeenCalled();

    threatSpy.mockRestore();
  });

  it('should NOT run outbound SSRF check when outboundSsrfProtection is false', async () => {
    const threatSpy = jest.spyOn(dashboard, 'sendThreatToDashboard').mockResolvedValue();

    hookFetch({
      ...mockOptions,
      features: { ...mockOptions.features, ssrfDetection: undefined, outboundSsrfProtection: false }
    });

    const response = await global.fetch('http://169.254.169.254/latest/meta-data', {
      headers: { 'Authorization': 'Bearer token' }
    });

    expect(response.status).toBe(200);
    expect(threatSpy).not.toHaveBeenCalled();

    threatSpy.mockRestore();
  });

  it('should read client IP from AsyncLocalStorage request context', async () => {
    const requestSpy = jest.spyOn(dashboard, 'sendRequestToDashboard').mockResolvedValue();

    hookFetch(mockOptions);

    await runWithRequestContext({ ip: '203.0.113.7' }, async () => {
      await global.fetch('https://api.example.com/users', {
        headers: { 'Authorization': 'Bearer token' }
      });
    });

    expect(requestSpy).toHaveBeenCalled();
    const eventArg = requestSpy.mock.calls[0][0];
    expect(eventArg.ip).toBe('203.0.113.7');

    requestSpy.mockRestore();
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
