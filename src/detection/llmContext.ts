const LLM_API_HOSTS = [
  'api.openai.com',
  'api.anthropic.com',
  'api.cohere.ai',
  'api.cohere.com',
  'generativelanguage.googleapis.com',
  'api.mistral.ai',
  'api.together.xyz',
  'api.groq.com',
  'api.perplexity.ai',
  'api.replicate.com',
  'api.huggingface.co',
  'inference.azure.com',
];

const LLM_PATH_PATTERNS = [
  /\/api\/ai\b/i,
  /\/api\/chat\b/i,
  /\/api\/completion[s]?\b/i,
  /\/api\/llm\b/i,
  /\/api\/generate\b/i,
  /\/api\/embed\b/i,
  /\/api\/embeddings?\b/i,
  /\/v1\/chat\/completions?\b/i,
  /\/v1\/completions?\b/i,
  /\/v1\/messages?\b/i,
  /\/v1\/embeddings?\b/i,
  /\/openai\//i,
  /\/anthropic\//i,
];

const LLM_HEADER_INDICATORS = [
  'x-openai-',
  'anthropic-',
  'x-ai-',
  'x-llm-',
];

export function isLlmRoute(url: string, headers?: Record<string, string>): boolean {
  try {
    const parsedUrl = new URL(url, 'http://localhost');
    const host = parsedUrl.hostname.toLowerCase();
    
    if (LLM_API_HOSTS.some(llmHost => host === llmHost || host.endsWith('.' + llmHost))) {
      return true;
    }
    
    const path = parsedUrl.pathname + parsedUrl.search;
    if (LLM_PATH_PATTERNS.some(pattern => pattern.test(path))) {
      return true;
    }
  } catch {
    if (LLM_PATH_PATTERNS.some(pattern => pattern.test(url))) {
      return true;
    }
  }

  if (headers) {
    const headerKeys = Object.keys(headers).map(k => k.toLowerCase());
    if (LLM_HEADER_INDICATORS.some(indicator => 
      headerKeys.some(key => key.startsWith(indicator))
    )) {
      return true;
    }
    
    const authHeader = headers['authorization'] || headers['Authorization'];
    if (authHeader && /^Bearer sk-[a-zA-Z0-9]/.test(authHeader)) {
      return true;
    }
  }

  return false;
}

export function detectLlmProvider(url: string, headers?: Record<string, string>): string | null {
  try {
    const parsedUrl = new URL(url, 'http://localhost');
    const host = parsedUrl.hostname.toLowerCase();
    
    if (host.includes('openai')) return 'openai';
    if (host.includes('anthropic')) return 'anthropic';
    if (host.includes('cohere')) return 'cohere';
    if (host.includes('google')) return 'google';
    if (host.includes('mistral')) return 'mistral';
    if (host.includes('groq')) return 'groq';
    if (host.includes('huggingface')) return 'huggingface';
    if (host.includes('azure')) return 'azure';
    if (host.includes('together')) return 'together';
    if (host.includes('replicate')) return 'replicate';
    if (host.includes('perplexity')) return 'perplexity';
  } catch {
    // Ignore parse errors
  }

  if (headers) {
    const headerKeys = Object.keys(headers).map(k => k.toLowerCase());
    if (headerKeys.some(k => k.startsWith('x-openai-'))) return 'openai';
    if (headerKeys.some(k => k.startsWith('anthropic-'))) return 'anthropic';
  }

  return null;
}
