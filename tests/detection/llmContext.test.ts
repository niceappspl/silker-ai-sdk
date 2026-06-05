import { isLlmRoute, detectLlmProvider } from '../../src/detection/llmContext';

describe('LLM Context Detection', () => {
  describe('isLlmRoute', () => {
    describe('URL-based detection', () => {
      it('should detect OpenAI API routes', () => {
        expect(isLlmRoute('https://api.openai.com/v1/chat/completions')).toBe(true);
        expect(isLlmRoute('https://api.openai.com/v1/completions')).toBe(true);
        expect(isLlmRoute('https://api.openai.com/v1/embeddings')).toBe(true);
      });

      it('should detect Anthropic API routes', () => {
        expect(isLlmRoute('https://api.anthropic.com/v1/messages')).toBe(true);
        expect(isLlmRoute('https://api.anthropic.com/v1/complete')).toBe(true);
      });

      it('should detect other LLM providers', () => {
        expect(isLlmRoute('https://api.cohere.ai/v1/generate')).toBe(true);
        expect(isLlmRoute('https://generativelanguage.googleapis.com/v1/models')).toBe(true);
        expect(isLlmRoute('https://api.mistral.ai/v1/chat/completions')).toBe(true);
      });

      it('should detect internal LLM routes', () => {
        expect(isLlmRoute('/api/ai/chat')).toBe(true);
        expect(isLlmRoute('/api/chat/completions')).toBe(true);
        expect(isLlmRoute('/api/llm/generate')).toBe(true);
        expect(isLlmRoute('/api/completion')).toBe(true);
        expect(isLlmRoute('/api/embeddings')).toBe(true);
      });

      it('should detect v1 API patterns', () => {
        expect(isLlmRoute('http://localhost:3000/v1/chat/completions')).toBe(true);
        expect(isLlmRoute('http://localhost:3000/v1/completions')).toBe(true);
        expect(isLlmRoute('http://localhost:3000/v1/messages')).toBe(true);
      });

      it('should not detect non-LLM routes', () => {
        expect(isLlmRoute('/api/users')).toBe(false);
        expect(isLlmRoute('/api/products')).toBe(false);
        expect(isLlmRoute('https://api.stripe.com/v1/charges')).toBe(false);
        expect(isLlmRoute('/health')).toBe(false);
      });
    });

    describe('Header-based detection', () => {
      it('should detect OpenAI headers', () => {
        const headers = { 'x-openai-organization': 'org-123' };
        expect(isLlmRoute('/api/proxy', headers)).toBe(true);
      });

      it('should detect Anthropic headers', () => {
        const headers = { 'anthropic-version': '2023-06-01' };
        expect(isLlmRoute('/api/proxy', headers)).toBe(true);
      });

      it('should detect OpenAI-style bearer tokens', () => {
        const headers = { authorization: 'Bearer sk-abc123def456' };
        expect(isLlmRoute('/api/proxy', headers)).toBe(true);
      });

      it('should not detect generic auth headers', () => {
        const headers = { authorization: 'Bearer jwt-token-here' };
        expect(isLlmRoute('/api/users', headers)).toBe(false);
      });
    });
  });

  describe('detectLlmProvider', () => {
    it('should detect OpenAI', () => {
      expect(detectLlmProvider('https://api.openai.com/v1/chat/completions')).toBe('openai');
    });

    it('should detect Anthropic', () => {
      expect(detectLlmProvider('https://api.anthropic.com/v1/messages')).toBe('anthropic');
    });

    it('should detect Google', () => {
      expect(detectLlmProvider('https://generativelanguage.googleapis.com/v1/models')).toBe('google');
    });

    it('should detect Cohere', () => {
      expect(detectLlmProvider('https://api.cohere.ai/generate')).toBe('cohere');
    });

    it('should detect Mistral', () => {
      expect(detectLlmProvider('https://api.mistral.ai/v1/chat/completions')).toBe('mistral');
    });

    it('should return null for unknown providers', () => {
      expect(detectLlmProvider('/api/custom-llm')).toBeNull();
      expect(detectLlmProvider('https://api.example.com/chat')).toBeNull();
    });

    it('should detect provider from headers', () => {
      const openaiHeaders = { 'x-openai-organization': 'org-123' };
      expect(detectLlmProvider('/api/proxy', openaiHeaders)).toBe('openai');

      const anthropicHeaders = { 'anthropic-version': '2023-06-01' };
      expect(detectLlmProvider('/api/proxy', anthropicHeaders)).toBe('anthropic');
    });
  });
});
