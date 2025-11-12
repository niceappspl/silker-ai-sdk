"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const apiSchema_1 = require("../../src/validation/apiSchema");
describe('validateApiSchema', () => {
    const baseEvent = {
        method: 'GET',
        url: '/api/test',
        timestamp: Date.now()
    };
    describe('User/Account endpoints', () => {
        it('should validate required fields for user endpoint', () => {
            const event = {
                ...baseEvent,
                url: '/api/user/123',
                payload: JSON.stringify({ id: 123, email: 'user@example.com', name: 'John' })
            };
            const result = (0, apiSchema_1.validateApiSchema)(event, JSON.parse(event.payload));
            expect(result.valid).toBe(true);
        });
        it('should detect missing required fields', () => {
            const event = {
                ...baseEvent,
                url: '/api/user',
                payload: JSON.stringify({ age: 30 })
            };
            const result = (0, apiSchema_1.validateApiSchema)(event, JSON.parse(event.payload));
            expect(result.valid).toBe(false);
            expect(result.errors).toContain('User/Account endpoint missing required fields');
        });
        it('should validate email format', () => {
            const event = {
                ...baseEvent,
                url: '/api/user',
                payload: JSON.stringify({ email: 'invalid-email', name: 'John' })
            };
            const result = (0, apiSchema_1.validateApiSchema)(event, JSON.parse(event.payload));
            expect(result.valid).toBe(false);
            expect(result.errors).toContain('Invalid email format');
        });
        it('should allow valid email format', () => {
            const event = {
                ...baseEvent,
                url: '/api/user',
                payload: JSON.stringify({ email: 'user@example.com', name: 'John' })
            };
            const result = (0, apiSchema_1.validateApiSchema)(event, JSON.parse(event.payload));
            expect(result.errors).not.toContain('Invalid email format');
        });
        it('should check nested data structure', () => {
            const event = {
                ...baseEvent,
                url: '/api/user',
                payload: JSON.stringify({ data: { id: 123, email: 'user@example.com' } })
            };
            const result = (0, apiSchema_1.validateApiSchema)(event, JSON.parse(event.payload));
            expect(result.valid).toBe(true);
        });
    });
    describe('API endpoints', () => {
        it('should validate API response structure', () => {
            const event = {
                ...baseEvent,
                url: '/api/users',
                payload: JSON.stringify({ data: [] })
            };
            const result = (0, apiSchema_1.validateApiSchema)(event, JSON.parse(event.payload));
            expect(result.valid).toBe(true);
        });
        it('should detect invalid API response structure', () => {
            const event = {
                ...baseEvent,
                url: '/api/users',
                payload: 'not-an-object'
            };
            try {
                const result = (0, apiSchema_1.validateApiSchema)(event, 'not-an-object');
                // Jeśli JSON.parse się nie powiedzie, funkcja zwróci 'Invalid JSON payload'
                expect(result.valid).toBe(false);
                expect(result.errors.length).toBeGreaterThan(0);
            }
            catch (e) {
                // Jeśli payload nie jest poprawnym JSON, funkcja powinna to obsłużyć
                const result = (0, apiSchema_1.validateApiSchema)(event, 'not-an-object');
                expect(result.valid).toBe(false);
            }
        });
        it('should validate list/search endpoints', () => {
            const event = {
                ...baseEvent,
                url: '/api/users/list',
                payload: JSON.stringify({ data: [{ id: 1 }, { id: 2 }] })
            };
            const result = (0, apiSchema_1.validateApiSchema)(event, JSON.parse(event.payload));
            expect(result.valid).toBe(true);
        });
        it('should detect invalid list endpoint structure', () => {
            const event = {
                ...baseEvent,
                url: '/api/users/search',
                payload: JSON.stringify({ data: 'not-an-array' })
            };
            const result = (0, apiSchema_1.validateApiSchema)(event, JSON.parse(event.payload));
            expect(result.valid).toBe(false);
            expect(result.errors).toContain('List/search endpoints should have data array or object');
        });
    });
    describe('URL parameters', () => {
        it('should validate ID format in URL', () => {
            const event = {
                ...baseEvent,
                url: '/api/user/123'
            };
            const result = (0, apiSchema_1.validateApiSchema)(event, {});
            expect(result.valid).toBe(true);
        });
        it('should detect suspicious ID format', () => {
            const longId = '1'.repeat(51);
            const event = {
                ...baseEvent,
                url: `/api/user/${longId}`
            };
            const result = (0, apiSchema_1.validateApiSchema)(event, {});
            expect(result.valid).toBe(false);
            expect(result.errors).toContain('Suspicious ID format in URL');
        });
        it('should validate query parameters length', () => {
            const longValue = 'x'.repeat(1001);
            const event = {
                ...baseEvent,
                url: `/api/search?q=${longValue}`
            };
            const result = (0, apiSchema_1.validateApiSchema)(event, {});
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('value too long'))).toBe(true);
        });
        it('should detect SQL patterns in query parameters', () => {
            const event = {
                ...baseEvent,
                url: '/api/search?q=SELECT * FROM users'
            };
            const result = (0, apiSchema_1.validateApiSchema)(event, {});
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('suspicious SQL patterns'))).toBe(true);
        });
    });
    describe('Content-Type validation', () => {
        it('should validate Content-Type for JSON payload', () => {
            const event = {
                ...baseEvent,
                method: 'POST',
                payload: JSON.stringify({ name: 'John' }),
                headers: { 'content-type': 'application/json' }
            };
            const result = (0, apiSchema_1.validateApiSchema)(event, JSON.parse(event.payload));
            expect(result.errors).not.toContain('JSON payload should have application/json Content-Type');
        });
        it('should detect missing Content-Type for JSON payload', () => {
            const event = {
                ...baseEvent,
                method: 'POST',
                payload: JSON.stringify({ name: 'John' }),
                headers: { 'content-type': 'text/plain' }
            };
            const result = (0, apiSchema_1.validateApiSchema)(event, JSON.parse(event.payload));
            expect(result.valid).toBe(false);
            expect(result.errors).toContain('JSON payload should have application/json Content-Type');
        });
        it('should not check Content-Type for GET requests', () => {
            const event = {
                ...baseEvent,
                method: 'GET',
                payload: JSON.stringify({ name: 'John' }),
                headers: {}
            };
            const result = (0, apiSchema_1.validateApiSchema)(event, JSON.parse(event.payload));
            expect(result.errors).not.toContain('JSON payload should have application/json Content-Type');
        });
    });
    describe('Edge cases', () => {
        it('should return valid for empty payload', () => {
            const event = {
                ...baseEvent
            };
            const result = (0, apiSchema_1.validateApiSchema)(event);
            expect(result.valid).toBe(true);
        });
        it('should handle invalid JSON gracefully', () => {
            const event = {
                ...baseEvent,
                payload: 'invalid-json{'
            };
            const result = (0, apiSchema_1.validateApiSchema)(event, 'invalid-json{');
            expect(result.valid).toBe(false);
            expect(result.errors).toContain('Invalid JSON payload');
        });
    });
});
describe('validateOpenApiCompliance', () => {
    const baseEvent = {
        method: 'GET',
        url: '/api/test',
        timestamp: Date.now()
    };
    it('should validate error field as string', () => {
        const payload = { error: 'Something went wrong' };
        const result = (0, apiSchema_1.validateOpenApiCompliance)(baseEvent, payload);
        expect(result.compliant).toBe(true);
    });
    it('should validate error field as object', () => {
        const payload = { error: { code: 500, message: 'Error' } };
        const result = (0, apiSchema_1.validateOpenApiCompliance)(baseEvent, payload);
        expect(result.compliant).toBe(true);
    });
    it('should detect invalid error field type', () => {
        const payload = { error: 123 };
        const result = (0, apiSchema_1.validateOpenApiCompliance)(baseEvent, payload);
        expect(result.compliant).toBe(false);
        expect(result.issues).toContain('Error field should be string or object');
    });
    it('should validate message field as string', () => {
        const payload = { message: 'Success' };
        const result = (0, apiSchema_1.validateOpenApiCompliance)(baseEvent, payload);
        expect(result.compliant).toBe(true);
    });
    it('should detect invalid message field type', () => {
        const payload = { message: 123 };
        const result = (0, apiSchema_1.validateOpenApiCompliance)(baseEvent, payload);
        expect(result.compliant).toBe(false);
        expect(result.issues).toContain('Message field should be string');
    });
    it('should validate status code range', () => {
        const payload = { status: 200 };
        const result = (0, apiSchema_1.validateOpenApiCompliance)(baseEvent, payload);
        expect(result.compliant).toBe(true);
    });
    it('should detect invalid status code (too low)', () => {
        const payload = { status: 99 };
        const result = (0, apiSchema_1.validateOpenApiCompliance)(baseEvent, payload);
        expect(result.compliant).toBe(false);
        expect(result.issues).toContain('Invalid HTTP status code');
    });
    it('should detect invalid status code (too high)', () => {
        const payload = { status: 600 };
        const result = (0, apiSchema_1.validateOpenApiCompliance)(baseEvent, payload);
        expect(result.compliant).toBe(false);
        expect(result.issues).toContain('Invalid HTTP status code');
    });
    it('should validate boolean fields', () => {
        const payload = { success: true, ok: false, valid: true };
        const result = (0, apiSchema_1.validateOpenApiCompliance)(baseEvent, payload);
        expect(result.compliant).toBe(true);
    });
    it('should detect invalid boolean field type', () => {
        const payload = { success: 'true' };
        const result = (0, apiSchema_1.validateOpenApiCompliance)(baseEvent, payload);
        expect(result.compliant).toBe(false);
        expect(result.issues).toContain("Field 'success' should be boolean");
    });
    it('should handle invalid JSON structure', () => {
        const result = (0, apiSchema_1.validateOpenApiCompliance)(baseEvent, 'invalid-json');
        expect(result.compliant).toBe(false);
        expect(result.issues).toContain('Invalid JSON structure');
    });
    it('should return compliant for empty payload', () => {
        const result = (0, apiSchema_1.validateOpenApiCompliance)(baseEvent);
        expect(result.compliant).toBe(true);
    });
});
describe('performApiValidation', () => {
    const baseEvent = {
        method: 'GET',
        url: '/api/test',
        timestamp: Date.now()
    };
    it('should return valid for compliant API', () => {
        const event = {
            ...baseEvent,
            payload: JSON.stringify({ data: [{ id: 1 }] })
        };
        const result = (0, apiSchema_1.performApiValidation)(event);
        expect(result.valid).toBe(true);
    });
    it('should combine schema and OpenAPI validation warnings', () => {
        const event = {
            ...baseEvent,
            url: '/api/user',
            payload: JSON.stringify({ email: 'invalid-email', success: 'true' })
        };
        const result = (0, apiSchema_1.performApiValidation)(event);
        expect(result.valid).toBe(false);
        expect(result.warnings.length).toBeGreaterThan(1);
    });
    it('should handle invalid JSON payload', () => {
        const event = {
            ...baseEvent,
            payload: 'invalid-json{'
        };
        const result = (0, apiSchema_1.performApiValidation)(event);
        expect(result.valid).toBe(false);
        expect(result.warnings).toContain('API validation failed');
    });
    it('should return valid for empty payload', () => {
        const event = {
            ...baseEvent
        };
        const result = (0, apiSchema_1.performApiValidation)(event);
        expect(result.valid).toBe(true);
    });
});
