import nock from 'nock';
import { hookExpress, getVibeEmitter } from '../../src/hooks/express';
import { SilkerOptions } from '../../src/types';
import { clearRateLimitState } from '../../src/detection/rateLimit';
import { setGlobalOptions } from '../../src/detection/anomaly';
import * as dashboard from '../../src/cloud/dashboard';

describe('hookExpress', () => {
  const mockOptions: SilkerOptions = {
    apiKey: 'test-api-key',
    endpoint: 'https://test-silker.com/api',
    debug: false
  };

  const originalEnvApiKey = process.env.SILKER_API_KEY;

  beforeEach(() => {
    clearRateLimitState();
    setGlobalOptions(null);
    nock.cleanAll();
    delete process.env.SILKER_API_KEY;
  });

  afterAll(() => {
    if (originalEnvApiKey !== undefined) {
      process.env.SILKER_API_KEY = originalEnvApiKey;
    } else {
      delete process.env.SILKER_API_KEY;
    }
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
      headers: { 'authorization': 'Bearer token' },
      body: {}
    };
    const res: any = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      on: jest.fn()
    };
    const next = jest.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('should block requests with anomalies', async () => {
    nock('https://test-silker.com')
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
      json: jest.fn().mockReturnThis(),
      on: jest.fn()
    };
    const next = jest.fn();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  it('should handle missing IP gracefully', async () => {
    const middleware = hookExpress(mockOptions);
    const req: any = {
      method: 'GET',
      originalUrl: '/api/test',
      ip: undefined,
      connection: { remoteAddress: '192.168.1.1' },
      get: jest.fn().mockReturnValue('Mozilla/5.0'),
      headers: { 'authorization': 'Bearer token' },
      body: {}
    };
    const res: any = {
        on: jest.fn()
    };
    const next = jest.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  it('should block on cloud connection failure for threats', async () => {
    nock('https://test-silker.com')
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
      json: jest.fn().mockReturnThis(),
      on: jest.fn()
    };
    const next = jest.fn();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  it('should work with no options and resolve apiKey from SILKER_API_KEY env', async () => {
    process.env.SILKER_API_KEY = 'sk_test_env_key_123456789012345678901234567890';
    const requestSpy = jest.spyOn(dashboard, 'sendRequestToDashboard').mockResolvedValue();

    const middleware = hookExpress();
    expect(typeof middleware).toBe('function');

    const req: any = {
      method: 'GET',
      originalUrl: '/api/users',
      ip: '192.168.1.1',
      get: jest.fn().mockReturnValue('Mozilla/5.0'),
      headers: {},
      body: {}
    };
    const res: any = {
      statusCode: 200,
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      on: jest.fn()
    };
    const next = jest.fn();

    await middleware(req, res, next);
    expect(next).toHaveBeenCalled();

    // Trigger the finish handler — telemetry should be sent without appId,
    // using the apiKey resolved from env
    const finishCall = res.on.mock.calls.find((c: any[]) => c[0] === 'finish');
    expect(finishCall).toBeDefined();
    finishCall[1]();

    expect(requestSpy).toHaveBeenCalled();
    const optionsArg = requestSpy.mock.calls[0][3];
    expect(optionsArg.apiKey).toBe('sk_test_env_key_123456789012345678901234567890');
    expect(optionsArg.appId).toBeUndefined();

    requestSpy.mockRestore();
  });

  it('should run detection-only (no telemetry) when no apiKey can be resolved', async () => {
    const requestSpy = jest.spyOn(dashboard, 'sendRequestToDashboard').mockResolvedValue();

    const middleware = hookExpress();

    const req: any = {
      method: 'GET',
      originalUrl: '/api/users',
      ip: '192.168.1.2',
      get: jest.fn().mockReturnValue('Mozilla/5.0'),
      headers: {},
      body: {}
    };
    const res: any = {
      statusCode: 200,
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      on: jest.fn()
    };
    const next = jest.fn();

    await middleware(req, res, next);
    expect(next).toHaveBeenCalled();

    const finishCall = res.on.mock.calls.find((c: any[]) => c[0] === 'finish');
    finishCall[1]();

    expect(requestSpy).not.toHaveBeenCalled();

    requestSpy.mockRestore();
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

