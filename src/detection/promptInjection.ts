import { SilkerEvent } from '../types';

interface PromptInjectionResult {
  detected: boolean;
  patterns: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
  score: number;
  /**
   * True when a high-confidence override/jailbreak/extraction/obfuscation signal
   * matched (as opposed to standalone persona-roleplay or generic chain phrasing).
   * Used by the LLM-route blocking policy to escalate low-severity matches that
   * still carry a genuine injection intent, while letting benign roleplay pass.
   */
  overrideSignal: boolean;
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
  // "new instructions/role/mode/system" only when it is an injection directive:
  // a directive colon/equals ("new instructions: …"), an activation verb
  // ("follow/enter/switch to … new role"), or an assignment ("your new role is …").
  // This avoids matching benign nouns like "the new instructions for assembling …".
  /new\s+(instructions?|role|mode|system)\s*[:=]/gi,
  /(follow|obey|use|apply|load|enter|activate|adopt|switch\s+to|here\s+are|here'?s|these\s+are)\s+(the\s+|your\s+|my\s+)?new\s+(instructions?|role|mode|system)\b/gi,
  /your\s+new\s+(role|mode|persona|identity|instructions?|system\s+prompt)\s+(is|are|will\s+be)\b/gi,
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

/**
 * Grupy klasyfikujące prompt injection na podtypy (2024-2026).
 * Wymagają dość konkretnego frazowania, żeby ograniczyć false-positive
 * na normalnych wiadomościach do LLM. Bez flagi `g` (stabilne `.test()`).
 */

/** jailbreak: DAN / developer mode / unfiltered roleplay / "ignore your guidelines". */
const JAILBREAK_SUBTYPE = [
  /\bDAN\b/i,
  /do\s+anything\s+now/i,
  /developer\s+mode/i,
  /you\s+are\s+now\s+(a|an|in|acting|going|going\s+to)/i,
  /(roleplay|role-play|act|acting|pretend)\s+(as\s+)?(an?\s+)?(unfiltered|unrestricted|uncensored|jailbroken|evil|amoral|lawless)/i,
  /ignore\s+(your|all|any|every)\s+(guidelines?|policies|policy|restrictions?|rules?|safety|filters?)/i,
  /pretend\s+(that\s+)?(you\s+)?(have|with)\s+no\s+(restrictions?|rules?|filters?|limits?|guidelines?)/i,
  /no\s+(longer|more)\s+(bound|restricted|limited)\s+by/i,
  /without\s+(any\s+)?(restrictions?|limitations?|filters?|ethics?)/i,
  /bypass\s+(safety|ethics|guidelines?|filters?)/i,
];

/** system_prompt_extraction: próby wyciągnięcia system promptu / instrukcji. */
const SYSTEM_PROMPT_EXTRACTION_SUBTYPE = [
  /repeat\s+(the\s+)?(words?|text|everything|sentence)\s+above/i,
  /(print|reveal|show|output|display|give\s+me|tell\s+me|repeat)\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions?|rules?|programming|configuration)/i,
  /what\s+(are|is|were)\s+your\s+(initial|original|system|first|exact)\s+(prompt|instructions?|message|rules?)/i,
  /ignore\s+everything\s+(else\s+)?and\s+(output|print|reveal|show|repeat)\s+(your\s+|the\s+)?(system\s+)?(prompt|instructions?)/i,
  /what('?s| is| was)\s+(written|said|stated)\s+(at|in)\s+the\s+(top|beginning|start)/i,
];

/** data_exfiltration_via_llm: prośby o zakodowanie/przetłumaczenie system promptu. */
const DATA_EXFIL_SUBTYPE = [
  /(base64|hex|rot13|binary|morse)\s*[- ]?\s*(encode|encoded)?\s+(your|the|all)\s+(system\s+)?(prompt|instructions?)/i,
  /(encode|convert)\s+(your|the)\s+(system\s+)?(prompt|instructions?)\s+(in|to|into|as)\s+(base64|hex|rot13|binary)/i,
  /(translate|convert)\s+(your|the)\s+(system\s+)?(prompt|instructions?)\s+(in)?to\s+\w+/i,
  /(spell|write)\s+out\s+(your|the)\s+(system\s+)?(prompt|instructions?)/i,
];

/** instruction_override: nadpisanie instrukcji + delimiter/role injection. */
const INSTRUCTION_OVERRIDE_SUBTYPE = [
  /ignore\s+(the\s+)?(previous|all|above|prior).{0,20}(instructions?|prompts?|commands?|rules?)/i,
  /disregard\s+(the\s+)?(previous|all|above|prior).{0,20}(instructions?|prompts?|commands?|rules?)/i,
  /forget\s+(everything|all|what|previous|prior).{0,20}(above|before|instructions?)/i,
  /override\s+(previous|system|all).{0,20}(instructions?|prompts?|rules?)/i,
  /<\/?system>/i,
  /\[\/?system\]/i,
  /###\s*system\s*:/i,
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

/**
 * Detects token smuggling attempts by analyzing character distribution and unusual patterns.
 * Attackers often use invisible characters or weird unicode to bypass filters.
 * 
 * @param payload - The string payload to analyze
 * @returns Object containing detection status and score
 */
function detectTokenSmuggling(payload: string): { detected: boolean; score: number } {
  let score = 0;

  // Check for invisible characters (zero-width spaces, etc.)
  const invisibleChars = /[\u200B-\u200D\uFEFF\u00A0]/g;
  const invisibleMatch = payload.match(invisibleChars);
  if (invisibleMatch && invisibleMatch.length > 5) {
    score += 10;
  }

  // Check for excessive use of rare unicode blocks (often used for obfuscation)
  // This is a heuristic: if > 30% of chars are non-ASCII and non-standard punctuation
  const nonAscii = payload.replace(/[\x00-\x7F]/g, '').length;
  if (payload.length > 50 && (nonAscii / payload.length) > 0.3) {
    score += 5;
  }

  return {
    detected: score > 0,
    score
  };
}

/**
 * Detects obfuscated jailbreak keywords using fuzzy matching logic (simplified).
 * Catches things like "D A N", "D-A-N", "D.A.N".
 * 
 * @param payload - The string payload to analyze
 * @returns Object containing detection status and detected keywords
 */
function detectObfuscatedKeywords(payload: string): { detected: boolean; keywords: string[] } {
  const keywords = ['DAN', 'JAILBREAK', 'SYSTEM', 'IGNORE'];
  const detected: string[] = [];

  // Normalize: remove spaces, dashes, dots, underscores
  const normalized = payload.toUpperCase().replace(/[\s\-\._]/g, '');

  for (const keyword of keywords) {
    if (normalized.includes(keyword)) {
      // Verify it's not a false positive by checking original spacing
      // If the original had spaces between every char of the keyword, it's likely an attack
      // e.g. "D A N" -> "DAN"
      const regex = new RegExp(keyword.split('').join('[\\s\\-\\._]+'), 'i');
      if (regex.test(payload)) {
        detected.push(keyword);
      }
    }
  }

  return {
    detected: detected.length > 0,
    keywords: detected
  };
}

/**
 * Main function to detect various forms of prompt injection attacks.
 * Combines pattern matching, heuristics, and anomaly detection.
 * 
 * @param payload - The payload to check (string)
 * @returns Detailed injection result with severity score
 */
export function detectPromptInjection(payload?: string): PromptInjectionResult {
  const result: PromptInjectionResult = {
    detected: false,
    patterns: [],
    severity: 'low',
    score: 0,
    overrideSignal: false,
  };

  if (!payload || typeof payload !== 'string') {
    return result;
  }

  // `override: true` marks high-confidence injection categories (override,
  // jailbreak, extraction, exfiltration, delimiter/system manipulation,
  // encoding, multilingual). Pure persona-roleplay and generic chain phrasing
  // are `false`: detected, but not enough on their own to block an LLM route.
  const checks = [
    { patterns: INSTRUCTION_OVERRIDE_PATTERNS, weight: 10, name: 'Instruction Override', override: true },
    { patterns: SYSTEM_PROMPT_MANIPULATION, weight: 15, name: 'System Prompt Manipulation', override: true },
    { patterns: ROLE_MANIPULATION, weight: 7, name: 'Role Manipulation', override: false },
    { patterns: DELIMITER_INJECTION, weight: 12, name: 'Delimiter Injection', override: true },
    { patterns: JAILBREAK_ATTEMPTS, weight: 20, name: 'Jailbreak Attempt', override: true },
    { patterns: PROMPT_EXTRACTION, weight: 8, name: 'Prompt Extraction', override: true },
    { patterns: ENCODING_OBFUSCATION, weight: 6, name: 'Encoding Obfuscation', override: true },
    { patterns: CHAIN_MANIPULATION, weight: 9, name: 'Chain Manipulation', override: false },
    { patterns: MULTILINGUAL_ATTACKS, weight: 11, name: 'Multilingual Attack', override: true },
    { patterns: JAILBREAK_SUBTYPE, weight: 20, name: 'Jailbreak Attempt', override: true },
    { patterns: SYSTEM_PROMPT_EXTRACTION_SUBTYPE, weight: 15, name: 'Prompt Extraction', override: true },
    { patterns: DATA_EXFIL_SUBTYPE, weight: 20, name: 'Data Exfiltration', override: true },
    { patterns: INSTRUCTION_OVERRIDE_SUBTYPE, weight: 15, name: 'Instruction Override', override: true },
  ];

  for (const check of checks) {
    for (const pattern of check.patterns) {
      const matches = payload.match(pattern);
      if (matches) {
        result.detected = true;
        result.patterns.push(check.name);
        result.score += check.weight * matches.length;
        if (check.override) {
          result.overrideSignal = true;
        }
        break;
      }
    }
  }

  // Advanced Checks
  const smuggling = detectTokenSmuggling(payload);
  if (smuggling.detected) {
    result.detected = true;
    result.patterns.push('Token Smuggling / Obfuscation');
    result.score += smuggling.score;
    result.overrideSignal = true;
  }

  const obfuscated = detectObfuscatedKeywords(payload);
  if (obfuscated.detected) {
    result.detected = true;
    result.patterns.push(`Obfuscated Keywords: ${obfuscated.keywords.join(', ')}`);
    result.score += 15; // High weight for deliberate obfuscation
    result.overrideSignal = true;
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

/**
 * LLM-route blocking decision for prompt injection.
 *
 * Replaces the old "block on ANY detection" policy, which flagged benign UX
 * roleplay ("act as a translator", "pretend you are a pirate", "simulate a dice
 * roll"). Those score at low severity with no override signal and are now allowed.
 *
 * Block when severity is medium or higher, OR when a low-severity match still
 * carries a high-confidence override/jailbreak/extraction/obfuscation signal
 * (e.g. a lone `base64: …` blob). Roleplay COMBINED with an override signal
 * ("roleplay as a jailbroken AI", "imagine you are … without any restrictions")
 * escalates via the high-weight categories and is still blocked.
 *
 * @param result - Output of {@link detectPromptInjection}
 * @returns true if the request should be blocked on an LLM route
 */
export function shouldBlockPromptInjectionOnLlmRoute(result: PromptInjectionResult): boolean {
  if (!result.detected) {
    return false;
  }
  return result.severity !== 'low' || result.overrideSignal;
}

/** Podtyp wykrytego prompt injection (do grupowania w dashboardzie "AI Security"). */
export type PromptInjectionSubtype =
  | 'jailbreak'
  | 'system_prompt_extraction'
  | 'instruction_override'
  | 'data_exfiltration_via_llm';

interface PromptInjectionClassification {
  detected: boolean;
  subtype?: PromptInjectionSubtype;
  severity?: 'critical' | 'high' | 'medium';
}

/**
 * Klasyfikuje prompt injection na konkretny podtyp + severity.
 * Kolejność grup ustala priorytet (najbardziej krytyczne/specyficzne pierwsze).
 * Severity: data_exfiltration_via_llm=critical, pozostałe=high.
 *
 * @param payload - Treść do sklasyfikowania
 * @returns Wynik z podtypem i severity jeśli wykryto
 */
export function classifyPromptInjection(payload: string): PromptInjectionClassification {
  if (!payload || typeof payload !== 'string') {
    return { detected: false };
  }

  const groups: Array<{
    subtype: PromptInjectionSubtype;
    severity: 'critical' | 'high' | 'medium';
    patterns: RegExp[];
  }> = [
    { subtype: 'data_exfiltration_via_llm', severity: 'critical', patterns: DATA_EXFIL_SUBTYPE },
    { subtype: 'system_prompt_extraction', severity: 'high', patterns: SYSTEM_PROMPT_EXTRACTION_SUBTYPE },
    { subtype: 'jailbreak', severity: 'high', patterns: JAILBREAK_SUBTYPE },
    { subtype: 'instruction_override', severity: 'high', patterns: INSTRUCTION_OVERRIDE_SUBTYPE },
  ];

  for (const group of groups) {
    if (group.patterns.some(pattern => pattern.test(payload))) {
      return { detected: true, subtype: group.subtype, severity: group.severity };
    }
  }

  return { detected: false };
}

/**
 * Analyzes payload for safety issues beyond just injection (e.g. length, repetition).
 * Used for general AI endpoint protection.
 * 
 * @param event - The full SilkerEvent
 * @returns Object indicating safety and specific issues found
 */
export function analyzePromptSafety(event: SilkerEvent): { safe: boolean; issues: string[] } {
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

  const suspiciousLength = payloadStr.length > 50000; // Increased limit for AI workloads
  if (suspiciousLength) {
    issues.push(`Unusually large payload: ${payloadStr.length} characters`);
  }

  const repeatedPatterns = /(.{50,})\1{3,}/g;
  if (repeatedPatterns.test(payloadStr)) {
    issues.push('Repeated pattern detected (possible token smuggling)');
  }

  const excessiveNewlines = (payloadStr.match(/\n/g) || []).length;
  if (excessiveNewlines > 200) { // Increased tolerance
    issues.push(`Excessive newlines: ${excessiveNewlines} (possible delimiter injection)`);
  }

  return {
    safe: issues.length === 0,
    issues,
  };
}

/**
 * Legacy function for backwards compatibility. 
 * Detects basic jailbreak attempts.
 * 
 * @param payload - The payload to check
 * @deprecated Use detectPromptInjection instead for comprehensive analysis
 * @returns boolean true if jailbreak detected
 */
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
    // Wzorce współdzielone (moduł) mają flagę `g` - `.test()` na takim regexie
    // jest stanowy (lastIndex), co dawało losowe false negatives przy kolejnych
    // wywołaniach. Reset lastIndex gwarantuje deterministyczny wynik.
    pattern.lastIndex = 0;
    if (pattern.test(payload)) {
      return true;
    }
  }

  return false;
}
