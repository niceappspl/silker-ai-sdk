import nock from 'nock';
import { hookExpress, getVibeEmitter } from '../../src/hooks/express';
import { VibeGuardOptions } from '../../src/types';

describe('hookExpress', () => {
  const mockOptions: VibeGuardOptions = {
    apiKey: 'test-api-key',
    endpoint: 'https://test-vibeguard.com/api',
    debug: false
  };

  beforeEach(() => {
    nock.cleanAll();
  });

  it('should return Express middleware function', () => {
    const middleware = hookExpress(mockOptions);
    expect(typeof middleware).toBe('function');
    expect(middleware.length).toBe(3);
  });

  it('should allow legitimate requests', async () => {
    const middleware = hookExpress(mockOptions);
    const req: any = {
      method: 'GET',
      originalUrl: '/api/users',
      ip: '192.168.1.1',
      get: jest.fn().mockReturnValue('Mozilla/5.0'),
      headers: {},
      body: {}
    };
    const res: any = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis()
    };
    const next = jest.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('should block requests with anomalies', async () => {
    nock('https://test-vibeguard.com')
      .post('/api')
      .reply(200, { block: true, alertId: 'alert-123' });

    const middleware = hookExpress(mockOptions);
    const req: any = {
      method: 'POST',
      originalUrl: '/api/login',
      ip: '192.168.1.1',
      get: jest.fn().mockReturnValue('Mozilla/5.0'),
      headers: {},
      body: { query: "'; DROP TABLE users; --" }
    };
    const res: any = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis()
    };
    const next = jest.fn();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({
      error: 'Request blocked by VibeGuard',
      alertId: 'alert-123'
    });
    expect(next).not.toHaveBeenCalled();
  });

  it('should allow requests when cloud says allow', async () => {
    nock('https://test-vibeguard.com')
      .post('/api')
      .reply(200, { block: false });

    const middleware = hookExpress(mockOptions);
    const req: any = {
      method: 'POST',
      originalUrl: '/api/login',
      ip: '192.168.1.1',
      get: jest.fn().mockReturnValue('Mozilla/5.0'),
      headers: {},
      body: { query: "'; DROP TABLE users; --" }
    };
    const res: any = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis()
    };
    const next = jest.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  it('should emit request event', async () => {
    const middleware = hookExpress(mockOptions);
    const emitter = getVibeEmitter();
    const eventSpy = jest.fn();
    emitter.on('request', eventSpy);

    const req: any = {
      method: 'GET',
      originalUrl: '/api/test',
      ip: '192.168.1.1',
      get: jest.fn().mockReturnValue('Mozilla/5.0'),
      headers: {},
      body: {}
    };
    const res: any = {};
    const next = jest.fn();

    await middleware(req, res, next);

    expect(eventSpy).toHaveBeenCalled();
    const emittedEvent = eventSpy.mock.calls[0][0];
    expect(emittedEvent.method).toBe('GET');
    expect(emittedEvent.url).toBe('/api/test');
  });

  it('should handle missing IP gracefully', async () => {
    const middleware = hookExpress(mockOptions);
    const req: any = {
      method: 'GET',
      originalUrl: '/api/test',
      ip: undefined,
      connection: { remoteAddress: '192.168.1.1' },
      get: jest.fn().mockReturnValue('Mozilla/5.0'),
      headers: {},
      body: {}
    };
    const res: any = {};
    const next = jest.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  it('should handle cloud connection failure gracefully', async () => {
    nock('https://test-vibeguard.com')
      .post('/api')
      .reply(500);

    const middleware = hookExpress(mockOptions);
    const req: any = {
      method: 'POST',
      originalUrl: '/api/login',
      ip: '192.168.1.1',
      get: jest.fn().mockReturnValue('Mozilla/5.0'),
      headers: {},
      body: { query: "'; DROP TABLE users; --" }
    };
    const res: any = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis()
    };
    const next = jest.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });
});

describe('getVibeEmitter', () => {
  it('should return EventEmitter instance', () => {
    const emitter = getVibeEmitter();
    expect(emitter).toBeDefined();
    expect(typeof emitter.on).toBe('function');
    expect(typeof emitter.emit).toBe('function');
  });

  it('should return same emitter instance', () => {
    const emitter1 = getVibeEmitter();
    const emitter2 = getVibeEmitter();
    expect(emitter1).toBe(emitter2);
  });
});

