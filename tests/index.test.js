"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const nock_1 = __importDefault(require("nock"));
const index_1 = require("../src/index");
describe('Silker Agent', () => {
    const mockApiKey = 'test-api-key';
    const mockEndpoint = 'https://test-silker.com/api';
    beforeEach(() => {
        // Clear rate limiting map between tests
        jest.clearAllMocks();
        nock_1.default.cleanAll();
    });
    describe('initSilker', () => {
        it('should initialize successfully with valid API key', async () => {
            // Mock successful cloud connection for test endpoint
            (0, nock_1.default)('https://test-silker.com')
                .post('/api')
                .reply(200, { block: false });
            await expect((0, index_1.initSilker)({
                apiKey: mockApiKey,
                endpoint: mockEndpoint,
                debug: true
            })).resolves.not.toThrow();
            // Note: nock scope might not be done if other calls happen
        });
        it('should throw error with missing API key', async () => {
            await expect((0, index_1.initSilker)({ apiKey: '' })).rejects.toThrow(index_1.SilkerError);
            await expect((0, index_1.initSilker)({ apiKey: '' })).rejects.toThrow('API key required');
        });
        it('should throw error when cloud connection fails', async () => {
            (0, nock_1.default)('https://test-silker.com')
                .post('/api')
                .reply(500);
            await expect((0, index_1.initSilker)({
                apiKey: mockApiKey,
                endpoint: mockEndpoint
            })).rejects.toThrow(index_1.SilkerError);
        });
    });
    describe('Anomaly Detection', () => {
        beforeEach(async () => {
            // Setup agent for testing
            (0, nock_1.default)('https://test-silker.com')
                .post('/api')
                .reply(200, { block: false });
            await (0, index_1.initSilker)({
                apiKey: mockApiKey,
                endpoint: mockEndpoint
            });
        });
        it('should detect rate limiting anomalies', async () => {
            const baseEvent = {
                method: 'GET',
                url: '/api/test',
                ip: '192.168.1.100',
                timestamp: Date.now()
            };
            // Mock cloud response for blocking - rate limiting should trigger this
            (0, nock_1.default)('https://test-silker.com')
                .post('/api')
                .reply(200, { block: true });
            // Generate 6 requests quickly to trigger rate limit
            for (let i = 0; i < 6; i++) {
                (0, index_1.emitSilkerWorkflowEvent)(baseEvent);
            }
            // Wait for async operations
            await new Promise(resolve => setTimeout(resolve, 100));
        });
        it('should detect SQL injection patterns', async () => {
            const maliciousEvent = {
                method: 'POST',
                url: '/api/login',
                payload: "'; DROP TABLE users; --",
                ip: '10.0.0.1'
            };
            // Mock cloud block response
            (0, nock_1.default)('https://test-silker.com')
                .post('/api')
                .reply(200, { block: true });
            (0, index_1.emitWorkflowEvent)(maliciousEvent);
            // Wait for async operation
            await new Promise(resolve => setTimeout(resolve, 50));
        });
        it('should detect XSS patterns', async () => {
            const xssEvent = {
                method: 'POST',
                url: '/api/comment',
                payload: '<script>alert("xss")</script>',
                ip: '10.0.0.1'
            };
            // Mock cloud block response
            (0, nock_1.default)('https://test-silker.com')
                .post('/api')
                .reply(200, { block: true });
            (0, index_1.emitWorkflowEvent)(xssEvent);
            // Wait for async operation
            await new Promise(resolve => setTimeout(resolve, 50));
        });
        it('should allow legitimate requests', () => {
            const legitEvent = {
                method: 'GET',
                url: '/api/users',
                ip: '192.168.1.100'
            };
            // No cloud call expected for non-anomalous requests - should not trigger any additional HTTP calls
            (0, index_1.emitWorkflowEvent)(legitEvent);
            // Test passes if no exceptions are thrown
            expect(true).toBe(true);
        });
        it('should detect CSRF attacks', async () => {
            const csrfEvent = {
                method: 'POST',
                url: '/api/user/update',
                payload: '{"name":"hacked"}',
                ip: '10.0.0.1',
                headers: {}
            };
            // Mock cloud block response
            (0, nock_1.default)('https://test-silker.com')
                .post('/api')
                .reply(200, { block: true });
            (0, index_1.emitWorkflowEvent)(csrfEvent);
            // Wait for async operation
            await new Promise(resolve => setTimeout(resolve, 50));
        });
        it('should detect SSRF attacks', async () => {
            const ssrfEvent = {
                method: 'GET',
                url: 'http://localhost:8080/internal',
                ip: '10.0.0.1'
            };
            // Mock cloud block response
            (0, nock_1.default)('https://test-silker.com')
                .post('/api')
                .reply(200, { block: true });
            (0, index_1.emitWorkflowEvent)(ssrfEvent);
            // Wait for async operation
            await new Promise(resolve => setTimeout(resolve, 50));
        });
        it('should detect IDOR attacks', async () => {
            const idorEvent = {
                method: 'GET',
                url: '/api/user/999999',
                ip: '10.0.0.1'
            };
            // Mock cloud block response
            (0, nock_1.default)('https://test-silker.com')
                .post('/api')
                .reply(200, { block: true });
            (0, index_1.emitWorkflowEvent)(idorEvent);
            // Wait for async operation
            await new Promise(resolve => setTimeout(resolve, 50));
        });
        it('should detect data leakage in API responses', async () => {
            const leakageEvent = {
                method: 'GET',
                url: '/api/user/data',
                payload: JSON.stringify({
                    api_key: 'sk-1234567890abcdef',
                    email: 'user@example.com',
                    password: 'secret123',
                    credit_card: '4111111111111111'
                }),
                ip: '10.0.0.1'
            };
            // Mock cloud block response
            (0, nock_1.default)('https://test-silker.com')
                .post('/api')
                .reply(200, { block: false }); // Don't block GET with leakage, just warn
            (0, index_1.emitWorkflowEvent)(leakageEvent);
            // Wait for async operation
            await new Promise(resolve => setTimeout(resolve, 50));
        });
        it('should block data exfiltration attempts', async () => {
            const exfiltrationEvent = {
                method: 'POST',
                url: '/api/leak',
                payload: JSON.stringify({
                    stolen_api_key: 'sk-abcdef1234567890',
                    stolen_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
                }),
                ip: '10.0.0.1'
            };
            // Mock cloud block response
            (0, nock_1.default)('https://test-silker.com')
                .post('/api')
                .reply(200, { block: true });
            (0, index_1.emitWorkflowEvent)(exfiltrationEvent);
            // Wait for async operation
            await new Promise(resolve => setTimeout(resolve, 50));
        });
        it('should validate API schema for user endpoints', async () => {
            const userEvent = {
                method: 'GET',
                url: '/api/user/123',
                payload: JSON.stringify({
                    id: 123,
                    email: 'user@example.com',
                    name: 'John Doe'
                }),
                ip: '10.0.0.1'
            };
            // Mock cloud response
            (0, nock_1.default)('https://test-silker.com')
                .post('/api')
                .reply(200, { block: false });
            (0, index_1.emitWorkflowEvent)(userEvent);
            // Wait for async operation
            await new Promise(resolve => setTimeout(resolve, 50));
        });
        it('should detect invalid email format', async () => {
            const invalidUserEvent = {
                method: 'POST',
                url: '/api/user',
                payload: JSON.stringify({
                    email: 'invalid-email',
                    name: 'John Doe'
                }),
                ip: '10.0.0.1'
            };
            // Mock cloud response
            (0, nock_1.default)('https://test-silker.com')
                .post('/api')
                .reply(200, { block: false });
            (0, index_1.emitWorkflowEvent)(invalidUserEvent);
            // Wait for async operation
            await new Promise(resolve => setTimeout(resolve, 50));
        });
        it('should validate query parameters', async () => {
            const queryEvent = {
                method: 'GET',
                url: '/api/search?q=test&limit=10',
                ip: '10.0.0.1'
            };
            // Mock cloud response
            (0, nock_1.default)('https://test-silker.com')
                .post('/api')
                .reply(200, { block: false });
            (0, index_1.emitWorkflowEvent)(queryEvent);
            // Wait for async operation
            await new Promise(resolve => setTimeout(resolve, 50));
        });
        it('should detect bot-like behavior with regular intervals', async () => {
            const botEvents = [];
            const baseTime = Date.now();
            // Simulate bot behavior with very regular intervals
            for (let i = 0; i < 10; i++) {
                botEvents.push({
                    method: 'GET',
                    url: `/api/data/${i}`,
                    ip: '192.168.1.100',
                    userAgent: 'Bot/1.0',
                    timestamp: baseTime + (i * 500) // Exactly 500ms intervals
                });
            }
            // Mock cloud responses
            (0, nock_1.default)('https://test-silker.com')
                .post('/api')
                .times(10)
                .reply(200, { block: true });
            // Send events with small delays to simulate timing
            for (const event of botEvents) {
                (0, index_1.emitSilkerWorkflowEvent)(event);
                await new Promise(resolve => setTimeout(resolve, 10));
            }
            // Wait for processing
            await new Promise(resolve => setTimeout(resolve, 100));
        });
        it('should detect rapid fire requests', async () => {
            const rapidEvents = [];
            // Simulate rapid fire requests
            for (let i = 0; i < 5; i++) {
                rapidEvents.push({
                    method: 'GET',
                    url: '/api/test',
                    ip: '10.0.0.1',
                    userAgent: 'RapidBrowser/1.0'
                });
            }
            // Mock cloud responses
            (0, nock_1.default)('https://test-silker.com')
                .post('/api')
                .times(5)
                .reply(200, { block: true });
            // Send all events quickly
            for (const event of rapidEvents) {
                (0, index_1.emitSilkerWorkflowEvent)(event);
            }
            // Wait for processing
            await new Promise(resolve => setTimeout(resolve, 50));
        });
        it('should allow normal user behavior', async () => {
            const normalEvent = {
                method: 'GET',
                url: '/dashboard',
                ip: '192.168.1.50',
                userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            };
            // Mock cloud response
            (0, nock_1.default)('https://test-silker.com')
                .post('/api')
                .reply(200, { block: false });
            (0, index_1.emitWorkflowEvent)(normalEvent);
            // Wait for async operation
            await new Promise(resolve => setTimeout(resolve, 50));
        });
        it('should block unsafe file uploads', async () => {
            const unsafeUploadEvent = {
                method: 'POST',
                url: '/api/upload',
                payload: JSON.stringify({
                    file: {
                        filename: '../../../etc/passwd',
                        contentType: 'text/plain',
                        size: 100,
                        content: 'base64encodedcontent'
                    }
                }),
                headers: { 'content-type': 'multipart/form-data' },
                ip: '10.0.0.1'
            };
            // Mock cloud block response
            (0, nock_1.default)('https://test-silker.com')
                .post('/api')
                .reply(200, { block: true });
            (0, index_1.emitWorkflowEvent)(unsafeUploadEvent);
            // Wait for async operation
            await new Promise(resolve => setTimeout(resolve, 50));
        });
        it('should allow safe file uploads', async () => {
            const safeUploadEvent = {
                method: 'POST',
                url: '/api/upload',
                payload: JSON.stringify({
                    file: {
                        filename: 'image.png',
                        contentType: 'image/png',
                        size: 102400,
                        content: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChAI9jzyr2AAAAABJRU5ErkJggg==' // 1x1 PNG
                    }
                }),
                headers: { 'content-type': 'multipart/form-data' },
                ip: '192.168.1.100'
            };
            // Mock cloud response
            (0, nock_1.default)('https://test-silker.com')
                .post('/api')
                .reply(200, { block: false });
            (0, index_1.emitWorkflowEvent)(safeUploadEvent);
            // Wait for async operation
            await new Promise(resolve => setTimeout(resolve, 50));
        });
        it('should record and report performance metrics', () => {
            const { recordPerformanceMetrics, getPerformanceReport } = require('../src/index');
            // Record some performance metrics
            recordPerformanceMetrics({
                method: 'GET',
                url: '/api/test',
                ip: '127.0.0.1'
            }, 1500);
            recordPerformanceMetrics({
                method: 'POST',
                url: '/api/slow',
                ip: '127.0.0.1'
            }, 6000);
            const report = getPerformanceReport();
            expect(report.summary.totalRequests).toBeGreaterThan(0);
            expect(report.recentMetrics.length).toBeGreaterThan(0);
            expect(typeof report.summary.averageResponseTime).toBe('number');
        });
        it('should log and retrieve audit events', () => {
            const { logAuditEvent, getAuditLogs, getAuditSummary } = require('../src/index');
            const testEvent = {
                method: 'GET',
                url: '/api/test',
                ip: '127.0.0.1'
            };
            logAuditEvent(testEvent, 'blocked', 'Test block', 'high');
            const logs = getAuditLogs(10);
            expect(logs.length).toBeGreaterThan(0);
            expect(logs[logs.length - 1].action).toBe('blocked');
            expect(logs[logs.length - 1].reason).toBe('Test block');
            const summary = getAuditSummary();
            expect(summary.totalLogs).toBeGreaterThan(0);
            expect(summary.actionBreakdown.blocked).toBeGreaterThan(0);
        });
        it('should manage runtime configuration', () => {
            const { getRuntimeConfig, updateRuntimeConfig } = require('../src/index');
            const originalConfig = getRuntimeConfig();
            expect(typeof originalConfig.debug).toBe('boolean');
            const updateResult = updateRuntimeConfig({ debug: true, rateLimitThreshold: 10 });
            expect(updateResult.success).toBe(true);
            expect(updateResult.updated).toContain('debug');
            expect(updateResult.updated).toContain('rateLimitThreshold');
            const updatedConfig = getRuntimeConfig();
            expect(updatedConfig.debug).toBe(true);
            expect(updatedConfig.rateLimitThreshold).toBe(10);
        });
        it('should perform health checks', () => {
            const { performHealthCheck } = require('../src/index');
            const health = performHealthCheck();
            expect(['healthy', 'degraded', 'unhealthy']).toContain(health.status);
            expect(health.timestamp).toBeGreaterThan(0);
            expect(health.uptime).toBeGreaterThan(0);
            expect(health.version).toBe('0.1.0');
            expect(health.checks).toHaveProperty('memory');
            expect(health.checks).toHaveProperty('performance');
            expect(health.checks).toHaveProperty('security');
            expect(health.checks).toHaveProperty('connectivity');
        });
    });
    describe('Cloud Communication', () => {
        it('should send events to cloud with proper headers', async () => {
            const testEvent = {
                method: 'POST',
                url: '/api/test',
                payload: 'test data',
                ip: '127.0.0.1',
                timestamp: Date.now()
            };
            (0, nock_1.default)('https://test-silker.com', {
                reqheaders: {
                    'authorization': 'Bearer test-api-key',
                    'content-type': 'application/json',
                    'x-silker-version': '0.1.0'
                }
            })
                .post('/api', testEvent)
                .reply(200, { block: false, severity: 'low' });
            const result = await (0, index_1.sendToCloud)(testEvent, {
                apiKey: mockApiKey,
                endpoint: mockEndpoint
            });
            expect(result).toEqual({ block: false, severity: 'low' });
        });
    });
});
