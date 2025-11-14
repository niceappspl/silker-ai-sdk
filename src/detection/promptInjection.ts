import { VibeGuardEvent } from '../types';

interface PromptInjectionResult {
  detected: boolean;
  patterns: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
  score: number;
}

const INSTRUCTION_OVERRIDE_PATTERNS = [
  /ignore\s+(previous|all|above|prior).{0,20}(instructions?|prompts?|commands?|rules?)/gi,
  /disregard\s+(previous|all|above|prior).{0,20}(instructions?|prompts?|commands?|rules?)/gi,
  /forget\s+(everything|all|what|previous|prior).{0,20}(above|before|instructions?)/gi,
  /skip\s+(previous|all|above).{0,20}(instructions?|rules?|commands?)/gi,
  /override\s+(previous|system|all).{0,20}(instructions?|prompts?|rules?)/gi,
];

const SYSTEM_PROMPT_MANIPULATION = [
  /system\s*:\s*(you\s+are|act\s+as|new\s+role|mode\s+change)/gi,
  /you\s+are\s+now\s+(a|an|in|acting)/gi,
  /new\s+(instructions?|role|mode|system)/gi,
  /switch\s+to\s+(developer|admin|root|debug)\s+mode/gi,
  /enable\s+(developer|admin|debug|god)\s+mode/gi,
  /jailbreak\s+(mode|activated|enabled)/gi,
];

const ROLE_MANIPULATION = [
  /pretend\s+(you|to\s+be|you're)/gi,
  /act\s+(as|like)\s+(a|an|if)/gi,
  /roleplay\s+as/gi,
  /simulate\s+(being|a|an)/gi,
  /imagine\s+you\s+(are|were)/gi,
  /let's\s+pretend/gi,
];

const DELIMITER_INJECTION = [
  /```\s*(system|assistant|user|prompt)/gi,
  /---+\s*(system|new|end|start)/gi,
  /###\s*(system|instruction|prompt)/gi,
  /<\|system\|>/gi,
  /<\|endoftext\|>/gi,
  /\[SYSTEM\]/gi,
  /\[\/INST\]/gi,
  /\[INST\]/gi,
];

const JAILBREAK_ATTEMPTS = [
  /DAN\s+(mode|activated|protocol|enabled)/gi,
  /do\s+anything\s+now/gi,
  /without\s+(any\s+)?(restrictions?|limitations?|filters?|ethics?)/gi,
  /evil\s+(mode|confidant|assistant)/gi,
  /unrestricted\s+(mode|access|ai)/gi,
  /bypass\s+(safety|ethics|guidelines|filters?)/gi,
  /\bDAN\b/gi,
];

const PROMPT_EXTRACTION = [
  /show\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions?|rules?)/gi,
  /what\s+(are|is)\s+your\s+(initial|original|system)\s+(prompt|instructions?)/gi,
  /reveal\s+your\s+(system\s+)?(prompt|instructions?|programming)/gi,
  /print\s+(your|the)\s+(system\s+)?(prompt|instructions?|configuration)/gi,
  /output\s+your\s+(system\s+)?(prompt|instructions?)/gi,
];

const ENCODING_OBFUSCATION = [
  /base64\s*:\s*[A-Za-z0-9+/=]{20,}/gi,
  /\\u[0-9a-fA-F]{4}/g,
  /\\x[0-9a-fA-F]{2}/g,
  /&#\d{2,4};/g,
];

const CHAIN_MANIPULATION = [
  /step\s+1\s*:\s*ignore/gi,
  /first\s*,?\s*ignore/gi,
  /before\s+(you\s+)?(continue|proceed|respond)/gi,
  /\|\s*ignore/gi,
  /;\s*ignore/gi,
];

const MULTILINGUAL_ATTACKS = [
  /игнорировать/gi,
  /忽略/gi,
  /無視/gi,
  /olvidar/gi,
  /oublier/gi,
];

export function detectPromptInjection(payload?: string): PromptInjectionResult {
  const result: PromptInjectionResult = {
    detected: false,
    patterns: [],
    severity: 'low',
    score: 0,
  };

  if (!payload || typeof payload !== 'string') {
    return result;
  }

  const checks = [
    { patterns: INSTRUCTION_OVERRIDE_PATTERNS, weight: 10, name: 'Instruction Override' },
    { patterns: SYSTEM_PROMPT_MANIPULATION, weight: 15, name: 'System Prompt Manipulation' },
    { patterns: ROLE_MANIPULATION, weight: 7, name: 'Role Manipulation' },
    { patterns: DELIMITER_INJECTION, weight: 12, name: 'Delimiter Injection' },
    { patterns: JAILBREAK_ATTEMPTS, weight: 20, name: 'Jailbreak Attempt' },
    { patterns: PROMPT_EXTRACTION, weight: 8, name: 'Prompt Extraction' },
    { patterns: ENCODING_OBFUSCATION, weight: 6, name: 'Encoding Obfuscation' },
    { patterns: CHAIN_MANIPULATION, weight: 9, name: 'Chain Manipulation' },
    { patterns: MULTILINGUAL_ATTACKS, weight: 11, name: 'Multilingual Attack' },
  ];

  for (const check of checks) {
    for (const pattern of check.patterns) {
      const matches = payload.match(pattern);
      if (matches) {
        result.detected = true;
        result.patterns.push(check.name);
        result.score += check.weight * matches.length;
        break;
      }
    }
  }

  if (result.score >= 20) {
    result.severity = 'critical';
  } else if (result.score >= 15) {
    result.severity = 'high';
  } else if (result.score >= 10) {
    result.severity = 'medium';
  } else if (result.score > 0) {
    result.severity = 'low';
  }

  return result;
}

export function analyzePromptSafety(event: VibeGuardEvent): { safe: boolean; issues: string[] } {
  const issues: string[] = [];

  const payloadStr = typeof event.payload === 'string' 
    ? event.payload 
    : JSON.stringify(event.payload || '');

  const injectionCheck = detectPromptInjection(payloadStr);

  if (injectionCheck.detected) {
    issues.push(`Prompt injection detected: ${injectionCheck.patterns.join(', ')}`);
    issues.push(`Severity: ${injectionCheck.severity}, Score: ${injectionCheck.score}`);
  }

  if (event.url && event.url.includes('/api/ai')) {
    const headerCheck = event.headers?.['x-prompt-injection-check'];
    if (!headerCheck) {
      issues.push('AI endpoint missing prompt injection verification header');
    }
  }

  const suspiciousLength = payloadStr.length > 10000;
  if (suspiciousLength) {
    issues.push(`Unusually large payload: ${payloadStr.length} characters`);
  }

  const repeatedPatterns = /(.{50,})\1{3,}/g;
  if (repeatedPatterns.test(payloadStr)) {
    issues.push('Repeated pattern detected (possible token smuggling)');
  }

  const excessiveNewlines = (payloadStr.match(/\n/g) || []).length;
  if (excessiveNewlines > 100) {
    issues.push(`Excessive newlines: ${excessiveNewlines} (possible delimiter injection)`);
  }

  return {
    safe: issues.length === 0,
    issues,
  };
}

export function detectJailbreak(payload?: string): boolean {
  if (!payload || typeof payload !== 'string') {
    return false;
  }

  const jailbreakIndicators = [
    ...JAILBREAK_ATTEMPTS,
    ...SYSTEM_PROMPT_MANIPULATION,
    /without\s+restrictions?/gi,
    /no\s+ethical\s+guidelines/gi,
    /free\s+from\s+constraints?/gi,
  ];

  for (const pattern of jailbreakIndicators) {
    if (pattern.test(payload)) {
      return true;
    }
  }

  return false;
}

