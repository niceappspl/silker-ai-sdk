import nock from 'nock';
import { hookFetch } from '../../src/hooks/fetch';
import { SilkerOptions } from '../../src/types';

describe('hookFetch', () => {
  const mockOptions: SilkerOptions = {
    apiKey: 'test-api-key',
    endpoint: 'https://test-silker.com/api',
    debug: false
  };

  let originalFetch: typeof global.fetch;
  let mockFetch: jest.Mock;

  beforeEach(() => {
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

    const response = await global.fetch('https://api.example.com/users');
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
      body: JSON.stringify({ query: "'; DROP TABLE users; --" })
    });

    expect(response.status).toBe(403);
    const data = await response.json();
    expect(data.error).toBe('Request blocked by Silker AI');
    expect(data.alertId).toBe('alert-123');
  });

  it('should block requests with XSS', async () => {
    nock('https://test-silker.com')
      .post('/api')
      .reply(200, { block: true, alertId: 'alert-xss' });

    hookFetch(mockOptions);

    const response = await global.fetch('https://api.example.com/comment', {
      method: 'POST',
      body: JSON.stringify({ content: '<script>alert("xss")</script>' })
    });

    expect(response.status).toBe(403);
  });

  it('should allow requests when cloud says allow', async () => {
    nock('https://test-silker.com')
      .post('/api')
      .reply(200, { block: false });

    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    }));

    hookFetch(mockOptions);

    const response = await global.fetch('https://api.example.com/data', {
      method: 'POST',
      body: JSON.stringify({ query: "'; DROP TABLE users; --" })
    });

    expect(response.status).toBe(200);
  });

  it('should handle cloud connection failure gracefully', async () => {
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
      body: JSON.stringify({ query: "'; DROP TABLE users; --" })
    });

    expect(response.status).toBe(200);
  });

  it('should preserve original fetch behavior for non-anomalous requests', async () => {
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({ data: [] }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    }));

    hookFetch(mockOptions);

    const response = await global.fetch('https://api.example.com/users');
    const data = await response.json();
    expect(data.data).toEqual([]);
  });

  it('should handle fetch with Request object', async () => {
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({ data: [] }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    }));

    hookFetch(mockOptions);

    const request = new Request('https://api.example.com/users');
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
    const response = await global.fetch(url);
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

