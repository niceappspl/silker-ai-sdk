"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const nock_1 = __importDefault(require("nock"));
const express_1 = require("../../src/hooks/express");
describe('hookExpress', () => {
    const mockOptions = {
        apiKey: 'test-api-key',
        endpoint: 'https://test-silker.com/api',
        debug: false
    };
    beforeEach(() => {
        nock_1.default.cleanAll();
    });
    it('should return Express middleware function', () => {
        const middleware = (0, express_1.hookExpress)(mockOptions);
        expect(typeof middleware).toBe('function');
        expect(middleware.length).toBe(3);
    });
    it('should allow legitimate requests', async () => {
        const middleware = (0, express_1.hookExpress)(mockOptions);
        const req = {
            method: 'GET',
            originalUrl: '/api/users',
            ip: '192.168.1.1',
            get: jest.fn().mockReturnValue('Mozilla/5.0'),
            headers: {},
            body: {}
        };
        const res = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn().mockReturnThis()
        };
        const next = jest.fn();
        await middleware(req, res, next);
        expect(next).toHaveBeenCalled();
        expect(res.status).not.toHaveBeenCalled();
    });
    it('should block requests with anomalies', async () => {
        (0, nock_1.default)('https://test-silker.com')
            .post('/api')
            .reply(200, { block: true, alertId: 'alert-123' });
        const middleware = (0, express_1.hookExpress)(mockOptions);
        const req = {
            method: 'POST',
            originalUrl: '/api/login',
            ip: '192.168.1.1',
            get: jest.fn().mockReturnValue('Mozilla/5.0'),
            headers: {},
            body: { query: "'; DROP TABLE users; --" }
        };
        const res = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn().mockReturnThis()
        };
        const next = jest.fn();
        await middleware(req, res, next);
        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith({
            error: 'Request blocked by Silker AI',
            alertId: 'alert-123'
        });
        expect(next).not.toHaveBeenCalled();
    });
    it('should allow requests when cloud says allow', async () => {
        (0, nock_1.default)('https://test-silker.com')
            .post('/api')
            .reply(200, { block: false });
        const middleware = (0, express_1.hookExpress)(mockOptions);
        const req = {
            method: 'POST',
            originalUrl: '/api/login',
            ip: '192.168.1.1',
            get: jest.fn().mockReturnValue('Mozilla/5.0'),
            headers: {},
            body: { query: "'; DROP TABLE users; --" }
        };
        const res = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn().mockReturnThis()
        };
        const next = jest.fn();
        await middleware(req, res, next);
        expect(next).toHaveBeenCalled();
    });
    it('should emit request event', async () => {
        const middleware = (0, express_1.hookExpress)(mockOptions);
        const emitter = (0, express_1.getVibeEmitter)();
        const eventSpy = jest.fn();
        emitter.on('request', eventSpy);
        const req = {
            method: 'GET',
            originalUrl: '/api/test',
            ip: '192.168.1.1',
            get: jest.fn().mockReturnValue('Mozilla/5.0'),
            headers: {},
            body: {}
        };
        const res = {};
        const next = jest.fn();
        await middleware(req, res, next);
        expect(eventSpy).toHaveBeenCalled();
        const emittedEvent = eventSpy.mock.calls[0][0];
        expect(emittedEvent.method).toBe('GET');
        expect(emittedEvent.url).toBe('/api/test');
    });
    it('should handle missing IP gracefully', async () => {
        const middleware = (0, express_1.hookExpress)(mockOptions);
        const req = {
            method: 'GET',
            originalUrl: '/api/test',
            ip: undefined,
            connection: { remoteAddress: '192.168.1.1' },
            get: jest.fn().mockReturnValue('Mozilla/5.0'),
            headers: {},
            body: {}
        };
        const res = {};
        const next = jest.fn();
        await middleware(req, res, next);
        expect(next).toHaveBeenCalled();
    });
    it('should handle cloud connection failure gracefully', async () => {
        (0, nock_1.default)('https://test-silker.com')
            .post('/api')
            .reply(500);
        const middleware = (0, express_1.hookExpress)(mockOptions);
        const req = {
            method: 'POST',
            originalUrl: '/api/login',
            ip: '192.168.1.1',
            get: jest.fn().mockReturnValue('Mozilla/5.0'),
            headers: {},
            body: { query: "'; DROP TABLE users; --" }
        };
        const res = {
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
        const emitter = (0, express_1.getVibeEmitter)();
        expect(emitter).toBeDefined();
        expect(typeof emitter.on).toBe('function');
        expect(typeof emitter.emit).toBe('function');
    });
    it('should return same emitter instance', () => {
        const emitter1 = (0, express_1.getVibeEmitter)();
        const emitter2 = (0, express_1.getVibeEmitter)();
        expect(emitter1).toBe(emitter2);
    });
});
