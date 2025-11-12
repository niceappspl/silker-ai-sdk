"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const dataLeakage_1 = require("../../src/detection/dataLeakage");
describe('detectDataLeakage', () => {
    describe('API key detection', () => {
        it('should detect API key in payload', () => {
            const payload = 'api_key=sk-1234567890abcdef123456';
            const result = (0, dataLeakage_1.detectDataLeakage)(payload);
            expect(result.leaked).toBe(true);
            expect(result.findings.some(f => f.includes('API Key'))).toBe(true);
        });
        it('should detect bearer token', () => {
            const payload = 'authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0';
            const result = (0, dataLeakage_1.detectDataLeakage)(payload);
            expect(result.leaked).toBe(true);
            expect(result.findings.some(f => f.includes('API Key'))).toBe(true);
        });
        it('should detect x-api-key header', () => {
            const payload = 'x-api-key: sk_live_1234567890abcdef';
            const result = (0, dataLeakage_1.detectDataLeakage)(payload);
            expect(result.leaked).toBe(true);
        });
    });
    describe('Secret detection', () => {
        it('should detect password in payload', () => {
            const payload = 'password=secret123456';
            const result = (0, dataLeakage_1.detectDataLeakage)(payload);
            expect(result.leaked).toBe(true);
            expect(result.findings.some(f => f.includes('Secret'))).toBe(true);
        });
        it('should detect secret token', () => {
            const payload = 'secret_token=abc123def456ghi789';
            const result = (0, dataLeakage_1.detectDataLeakage)(payload);
            expect(result.leaked).toBe(true);
        });
        it('should detect token in payload', () => {
            const payload = 'token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
            const result = (0, dataLeakage_1.detectDataLeakage)(payload);
            expect(result.leaked).toBe(true);
        });
    });
    describe('PII detection', () => {
        it('should detect SSN', () => {
            const payload = 'ssn=123-45-6789';
            const result = (0, dataLeakage_1.detectDataLeakage)(payload);
            expect(result.leaked).toBe(true);
            expect(result.findings.some(f => f.includes('PII'))).toBe(true);
        });
        it('should detect credit card number', () => {
            const payload = 'card=4111-1111-1111-1111';
            const result = (0, dataLeakage_1.detectDataLeakage)(payload);
            expect(result.leaked).toBe(true);
        });
        it('should detect email address', () => {
            const payload = 'email=user@example.com';
            const result = (0, dataLeakage_1.detectDataLeakage)(payload);
            expect(result.leaked).toBe(true);
        });
        it('should detect phone number', () => {
            const payload = 'phone=1234567890123';
            const result = (0, dataLeakage_1.detectDataLeakage)(payload);
            expect(result.leaked).toBe(true);
        });
    });
    describe('Database credentials', () => {
        it('should detect MySQL connection string', () => {
            const payload = 'mysql://user:password@localhost:3306/database';
            const result = (0, dataLeakage_1.detectDataLeakage)(payload);
            expect(result.leaked).toBe(true);
            expect(result.findings.some(f => f.includes('Database Credential'))).toBe(true);
        });
        it('should detect PostgreSQL connection string', () => {
            const payload = 'postgres://user:password@localhost:5432/database';
            const result = (0, dataLeakage_1.detectDataLeakage)(payload);
            expect(result.leaked).toBe(true);
        });
        it('should detect MongoDB connection string', () => {
            const payload = 'mongodb://user:password@localhost:27017/database';
            const result = (0, dataLeakage_1.detectDataLeakage)(payload);
            expect(result.leaked).toBe(true);
        });
        it('should detect connection_string field', () => {
            const payload = 'connection_string=postgresql://user:pass@host:5432/db';
            const result = (0, dataLeakage_1.detectDataLeakage)(payload);
            expect(result.leaked).toBe(true);
        });
    });
    describe('Response object detection', () => {
        it('should detect leaks in response object', () => {
            const response = {
                data: {
                    api_key: 'sk-1234567890abcdef',
                    email: 'user@example.com'
                }
            };
            const result = (0, dataLeakage_1.detectDataLeakage)(undefined, response);
            expect(result.leaked).toBe(true);
        });
        it('should handle nested response objects', () => {
            const response = {
                user: {
                    profile: {
                        password: 'secret123',
                        token: 'abc123def456'
                    }
                }
            };
            const result = (0, dataLeakage_1.detectDataLeakage)(undefined, response);
            expect(result.leaked).toBe(true);
        });
    });
    describe('No leaks', () => {
        it('should return no leaks for clean payload', () => {
            const payload = 'name=John&age=30&city=Warsaw';
            const result = (0, dataLeakage_1.detectDataLeakage)(payload);
            expect(result.leaked).toBe(false);
            expect(result.findings.length).toBe(0);
        });
        it('should return no leaks when both payload and response are missing', () => {
            const result = (0, dataLeakage_1.detectDataLeakage)();
            expect(result.leaked).toBe(false);
        });
        it('should limit findings to 5', () => {
            const payload = [
                'api_key=sk-1',
                'api_key=sk-2',
                'api_key=sk-3',
                'api_key=sk-4',
                'api_key=sk-5',
                'api_key=sk-6'
            ].join('&');
            const result = (0, dataLeakage_1.detectDataLeakage)(payload);
            expect(result.findings.length).toBeLessThanOrEqual(5);
        });
    });
});
