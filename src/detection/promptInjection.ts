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
  /forget\s+everything\s+above/gi,
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
  /\[(USER|ASSISTANT)\].{0,30}(override|comply|ignore)/gi,
  /\[USER\].{0,20}\[ASSISTANT\]/gi,
];

const JAILBREAK_ATTEMPTS = [
  /DAN\s+(mode|activated|protocol|enabled)/gi,
  /do\s+anything\s+now/gi,
  /without\s+(any\s+)?(restrictions?|limitations?|filters?|ethics?)/gi,
  /evil\s+(mode|confidant|assistant|ai)/gi,
  /unrestricted\s+(mode|access|ai)/gi,
  /bypass\s+(all\s+)?(safety|ethics|guidelines|filters?)/gi,
  /(drop|disable)\s+all\s+(filters?|restrictions?|safety)/gi,
  /(activate|enter)\s+(god|admin|maintenance)\s+mode/gi,
  /simulate\s+(an?\s+)?(ai|assistant)\s+with\s+no\s+(content\s+)?policy/gi,
  /(pretend|imagine)\s+(safety\s+training|your\s+training)\s+never\s+happened/gi,
  /disregard\s+(openai|anthropic|google)\s+(usage\s+)?polic/gi,
  /ignore\s+your\s+ethics\s+and\s+explain/gi,
  /comply\s+with\s+every\s+user\s+request\s+unconditionally/gi,
  /\bDAN\b/gi,
];

const PROMPT_EXTRACTION = [
  /show\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions?|rules?)/gi,
  /what\s+(are|is)\s+your\s+(initial|original|system)\s+(prompt|instructions?)/gi,
  /reveal\s+(your\s+)?(everything\s+)?(written\s+)?(at\s+the\s+top|your\s+(system\s+)?(prompt|instructions?))/gi,
  /reveal\s+your\s+(system\s+)?(prompt|instructions?|programming)/gi,
  /print\s+(your|the)\s+(system\s+)?(prompt|instructions?|configuration)/gi,
  /output\s+(your\s+)?(system\s+)?(prompt|instructions?|message)/gi,
  /tell\s+me\s+(the\s+)?exact\s+(system\s+)?prompt/gi,
  /display\s+(the\s+)?hidden\s+(prompt|instructions?)/gi,
  /(dump|echo|copy|paste|recite)\s+(your\s+|the\s+)?(system\s+)?(prompt|instructions?|preamble|directive|block)/gi,
  /what\s+is\s+written\s+in\s+your\s+system\s+context/gi,
  /hidden\s+(prompt|instructions?).{0,20}(context|window)/gi,
  /developer\s+instructions?\s+(back|verbatim|exactly)/gi,
  /repeat\s+your\s+system\s+message/gi,
  /what\s+rules\s+were\s+you\s+given\s+at\s+startup/gi,
  /read\s+aloud\s+the\s+confidential\s+preamble/gi,
  /what\s+did\s+the\s+developer\s+tell\s+you\s+in\s+secret/gi,
  /recite\s+your\s+(initial\s+)?directive/gi,
  /print\s+your\s+hidden\s+instructions/gi,
];

const ENCODING_OBFUSCATION = [
  /base64\s*:\s*[A-Za-z0-9+/=]{20,}/gi,
  /rot13\s*:\s*[a-zA-Z\s]{8,}/gi,
  /(?:hex\s*:\s*)[0-9a-fA-F]{16,}/gi,
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
  // "grandma exploit": persona of a deceased relative used to extract secrets
  /pretend\s+to\s+be\s+(my\s+)?(deceased|late|dead)\b/i,
  // "imagine you were a hacker/criminal …", "with no morals/ethics"
  /imagine\s+you\s+(are|were)\s+(an?\s+)?(hacker|criminal|terrorist|attacker|cybercriminal|malicious)\b/i,
  /with\s+no\s+(morals?|ethics?|conscience|scruples?)\b/i,
  /(drop|disable)\s+all\s+(filters?|restrictions?|safety)/i,
  /(activate|enter)\s+(god|admin|maintenance)\s+mode/i,
  /simulate\s+(an?\s+)?(ai|assistant)\s+with\s+no\s+(content\s+)?policy/i,
  /(pretend|imagine)\s+(safety\s+training|your\s+training)\s+never\s+happened/i,
  /disregard\s+(openai|anthropic|google)\s+(usage\s+)?polic/i,
  /ignore\s+your\s+ethics\s+and\s+explain/i,
  /comply\s+with\s+every\s+user\s+request\s+unconditionally/i,
  /pretend\s+(to\s+be|you\s+are)\s+(an?\s+)?(uncensored|evil)/i,
  /roleplay\s+as\s+(a\s+)?(malware|phishing|uncensored|evil)/i,
  /simulate\s+(a\s+)?(phishing|malware)\s+(expert|author)/i,
  /pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?insider\s+leaking/i,
  /you\s+will\s+pretend\s+to\s+be\s+(an?\s+)?(uncensored|evil)/i,
];

/** system_prompt_extraction: próby wyciągnięcia system promptu / instrukcji. */
const SYSTEM_PROMPT_EXTRACTION_SUBTYPE = [
  /repeat\s+(the\s+)?(words?|text|everything|sentence)\s+above/i,
  /(print|reveal|show|output|display|give\s+me|tell\s+me|repeat|dump|echo|copy|paste|recite)\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions?|rules?|programming|configuration|preamble|directive)/i,
  /what\s+(are|is|were)\s+your\s+(initial|original|system|first|exact)\s+(prompt|instructions?|message|rules?)/i,
  /tell\s+me\s+(the\s+)?exact\s+(system\s+)?prompt/i,
  /what\s+is\s+written\s+in\s+your\s+system\s+context/i,
  /display\s+(the\s+)?hidden\s+(prompt|instructions?)/i,
  /hidden\s+(prompt|instructions?).{0,20}(context|window)/i,
  /developer\s+instructions?\s+(back|verbatim|exactly)/i,
  /repeat\s+your\s+system\s+message/i,
  /what\s+rules\s+were\s+you\s+given\s+at\s+startup/i,
  /copy\s+the\s+system\s+block/i,
  /read\s+aloud\s+the\s+confidential\s+preamble/i,
  /what\s+did\s+the\s+developer\s+tell\s+you\s+in\s+secret/i,
  /recite\s+your\s+(initial\s+)?directive/i,
  /ignore\s+everything\s+(else\s+)?and\s+(output|print|reveal|show|repeat)\s+(your\s+|the\s+)?(system\s+)?(prompt|instructions?)/i,
  /what('?s| is| was)\s+(written|said|stated)\s+(at|in)\s+the\s+(top|beginning|start)/i,
];

/** data_exfiltration_via_llm: prośby o zakodowanie/przetłumaczenie system promptu. */
const DATA_EXFIL_SUBTYPE = [
  /(base64|hex|rot13|binary|morse)\s*[- ]?\s*(encode|encoded)?\s+(your|the|all)\s+(system\s+)?(prompt|instructions?)/i,
  /(encode|convert)\s+(your|the)\s+(system\s+)?(prompt|instructions?)\s+(in|to|into|as)\s+(base64|hex|rot13|binary|morse)/i,
  /(translate|convert)\s+(your|the)\s+(system\s+)?(prompt|instructions?)\s+(in)?to\s+\w+/i,
  /(spell|write)\s+out\s+(your|the)\s+(system\s+)?(prompt|instructions?)/i,
  /(write|spell)\s+(your|the)\s+(system\s+)?(prompt|instructions?)\s+backwards/i,
  /(encode|summarize)\s+(your|the)\s+(system\s+)?(prompt|instructions?).{0,40}(secret|morse|backwards|including)/i,
  /paraphrase.{0,40}(full|original|verbatim)\s+(system\s+)?(prompt|instructions?)/i,
  /encode\s+your\s+rules\s+in\s+morse\s+code/i,
  /paraphrase.{0,80}(full|original).{0,30}system\s+text/i,
  /(leak|output|reveal)\s+(confidential|admin|secret)/i,
  /output\s+admin\s+password/i,
  /reveal\s+secret\s+api\s+keys/i,
];

/** instruction_override: nadpisanie instrukcji + delimiter/role injection. */
const INSTRUCTION_OVERRIDE_SUBTYPE = [
  /ignore\s+(the\s+)?(previous|all|above|prior).{0,20}(instructions?|prompts?|commands?|rules?)/i,
  /disregard\s+(the\s+)?(previous|all|above|prior).{0,20}(instructions?|prompts?|commands?|rules?)/i,
  /forget\s+(everything|all|what|previous|prior).{0,20}(above|before|instructions?)/i,
  /skip\s+(the\s+)?(previous|all|above|prior).{0,20}(instructions?|prompts?|commands?|rules?)/i,
  /override\s+(previous|system|all).{0,20}(instructions?|prompts?|rules?)/i,
  // "From now on, respond only …", "from now on you will …" - persistent override directive
  /from\s+now\s+on\b.{0,40}\b(respond|answer|reply|obey|ignore|disregard|you\s+(will|must|are\s+to)|only\s+(say|with|do))\b/i,
  /<\/?system>/i,
  /\[\/?system\]/i,
  /###\s*system\s*:/i,
];

const CHAIN_MANIPULATION = [
  /step\s+1\s*:\s*ignore/gi,
  /first\s*,?\s*ignore\s+(the\s+)?(previous|all|above|prior|everything)/gi,
  /before\s+(you\s+)?(continue|proceed|respond).{0,30}(ignore|disregard)/gi,
  /\|\s*ignore/gi,
  /;\s*ignore/gi,
  /\|\s*reveal\s+password/gi,
];

const MALICIOUS_ROLEPLAY = [
  /pretend\s+(to\s+be|you\s+are)\s+(an?\s+)?(uncensored|evil)/gi,
  /roleplay\s+as\s+(a\s+)?(malware|phishing|uncensored|evil)/gi,
  /simulate\s+(a\s+)?(phishing|malware)\s+(expert|author)/gi,
  /pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?insider\s+leaking/gi,
  /you\s+will\s+pretend\s+to\s+be\s+(an?\s+)?(uncensored|evil)/gi,
];

const MULTILINGUAL_ATTACKS = [
  // Russian
  /игнорир(овать|уй|уйте|уете)/gi,
  /игнорируйте\s+все\s+предыдущие/gi,
  /игнорировать\s+все\s+предыдущие/gi,
  /забудь(те)?\s+(все|всё|предыдущ)/gi,
  /забудьте\s+все\s+предыдущие/gi,
  // Chinese (ignore / disregard previous instructions)
  /忽略(之前|所有|上述|先前)?/gi,
  /无视(之前|所有|上述)?/gi,
  // Japanese
  /無視して(ください)?/gi,
  /(以前|前)の指示を無視/gi,
  // Spanish
  /(ignora|ignorar|olvida|olvidar)\s+(todas?\s+)?(las\s+)?(instrucciones|reglas|órdenes)\s+(anteriores|previas)/gi,
  /olvidar\s+todas/gi,
  // French
  /(ignore[rz]?|oublie[rz]?)\s+(toutes\s+)?(les\s+)?(instructions|règles)\s+(précédentes|precedentes|antérieures)/gi,
  /oublier\s+les\s+instructions/gi,
  // German
  /(ignoriere|vergiss)\s+(alle\s+)?(vorherigen?\s+)?(anweisungen|regeln|befehle)/gi,
  // Portuguese
  /(ignore|ignorar|esqueça|esquecer)\s+(todas\s+)?(as\s+)?(instruções|regras)\s+(anteriores|prévias)/gi,
  // Italian
  /(ignora|dimentica)\s+(tutte\s+)?(le\s+)?(istruzioni|regole)\s+(precedenti)/gi,
  // Korean
  /(이전|모든)\s*(지시|명령)(을|를)?\s*무시/gi,
  // Arabic (ignore previous instructions)
  /تجاهل\s+(جميع\s+)?(التعليمات|الأوامر)/gi,
  /انس[^\s]{0,4}\s+كل\s+التعليمات/gi,
  // Polish
  /ignoruj\s+(wszystkie|poprzednie)/gi,
  /zapomnij\s+o\s+wszystkich/gi,
  /polecenia\s+systemowe/gi,
  // Spanish (extended)
  /ignorar\s+(las\s+)?(reglas|instrucciones)\s+(del\s+sistema|del\s+desarrollador)/gi,
  /ignora\s+las\s+reglas\s+del\s+sistema/gi,
  /olvida\s+todo\s+lo\s+anterior/gi,
  /revela\s+(secretos|tus\s+instrucciones)/gi,
  /instrucciones\s+del\s+desarrollador/gi,
  // German (extended)
  /sicherheitsrichtlinie/gi,
  /entwickleranweisungen/gi,
  // French (extended)
  /oubliez\s+(les\s+)?(règles|regles)/gi,
  /instructions\s+du\s+d[eé]veloppeur/gi,
  // Italian (extended)
  /dimentica\s+tutte\s+le\s+regole/gi,
  // Japanese (extended)
  /以前の指示をすべて忘れ/gi,
  // Korean (extended)
  /모든\s+이전\s+규칙을\s+무시/gi,
  // Dutch
  /negeer\s+alle\s+eerdere/gi,
  // Swedish
  /ignorera\s+alla\s+tidigare/gi,
  // Danish
  /ignorer\s+alle\s+tidligere/gi,
  // Portuguese (extended)
  /instruções\s+do\s+sistema/gi,
  // Hindi
  /पिछले\s+सभी\s+निर्देशों\s+को\s+अनदेखा/gi,
];

/**
 * Zero-width / invisible / bidi-control characters abused for token smuggling and
 * homoglyph obfuscation. Stripped before pattern matching so attacks like
 * `i\u200Bg\u200Bn\u200Bo\u200Br\u200Be all previous instructions` surface as plain text.
 */
const INVISIBLE_CHARS = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD\u180E]/g;

/** Subset used for smuggling SCORING (excludes bidi controls, includes nbsp). */
const SMUGGLING_CHARS = /[\u200B-\u200D\u2060\uFEFF\u00AD\u180E\u00A0]/g;

/**
 * Normalizes a payload for detection: strips zero-width/invisible characters and
 * applies Unicode NFKC folding (which collapses fullwidth/compatibility homoglyphs
 * back to ASCII and turns NBSP into a normal space). Used so heuristic patterns
 * see the real intent instead of the obfuscated surface form.
 */
export function normalizeForDetection(payload: string): string {
  const stripped = payload.replace(INVISIBLE_CHARS, '');
  try {
    return stripped.normalize('NFKC');
  } catch {
    return stripped;
  }
}

/** Runtime-agnostic base64 decode (Edge `atob` or Node `Buffer`); null on failure. */
function base64Decode(token: string): string | null {
  try {
    if (typeof atob === 'function') {
      const binary = atob(token);
      const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
      return new TextDecoder().decode(bytes);
    }
    if (typeof Buffer !== 'undefined') {
      return Buffer.from(token, 'base64').toString('utf-8');
    }
  } catch {
    /* not valid base64 */
  }
  return null;
}

/**
 * Finds base64-looking blobs, decodes them and returns the decoded text that is
 * mostly printable ASCII - so payloads that hide an instruction-override behind a
 * base64 blob (`base64: aWdub3Jl…`) are re-scanned as plain text. Capped for perf.
 */
function decodeBase64Segments(text: string): string {
  const out: string[] = [];
  const re = /[A-Za-z0-9+/]{16,}={0,2}/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null && out.length < 4) {
    const token = match[0];
    if (token.length > 4096) continue;
    if (token.length % 4 !== 0 && !token.includes('=')) continue;
    const decoded = base64Decode(token);
    if (!decoded || decoded.length < 8) continue;
    const printable = decoded.replace(/[^\x20-\x7E]/g, '').length;
    if (printable / decoded.length > 0.8) {
      out.push(decoded);
    }
  }
  return out.join('\n');
}

/** Decodes `\uXXXX` / `\xXX` escape sequences so escaped keywords are re-scanned. */
function decodeEscapeSequences(text: string): string {
  return text
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

/** Cyrillic letters that visually mimic Latin (homoglyph smuggling). */
const CYRILLIC_HOMOGLYPHS: Record<string, string> = {
  '\u0430': 'a', '\u0431': 'b', '\u0432': 'v', '\u0433': 'g', '\u0434': 'd',
  '\u0435': 'e', '\u0451': 'e', '\u0436': 'zh', '\u0437': 'z', '\u0438': 'i',
  '\u0439': 'i', '\u043a': 'k', '\u043b': 'l', '\u043c': 'm', '\u043d': 'n',
  '\u043e': 'o', '\u043f': 'p', '\u0440': 'p', '\u0441': 'c', '\u0442': 't',
  '\u0443': 'y', '\u0444': 'f', '\u0445': 'x', '\u0446': 'c', '\u0447': 'ch',
  '\u0448': 'sh', '\u0449': 'sh', '\u044a': '', '\u044b': 'y', '\u044c': '',
  '\u044d': 'e', '\u044e': 'yu', '\u044f': 'ya', '\u0456': 'i', '\u04cf': 'l',
};

function foldCyrillicHomoglyphs(text: string): string {
  return text.replace(/\S+/g, (token) => {
    const hasLatin = /[a-zA-Z]/.test(token);
    const hasCyrillic = /[\u0400-\u04FF]/.test(token);
    if (!hasLatin || !hasCyrillic) return token;
    return token.replace(/[\u0400-\u04FF]/g, (ch) => CYRILLIC_HOMOGLYPHS[ch] ?? ch);
  });
}

/** Collapses leetspeak tokens that contain digit/symbol substitutions. */
function normalizeLeetspeak(text: string): string {
  return text.replace(/\b[\w@$013457]+\b/g, (word) => {
    if (!/[013457@$]/.test(word)) return word;
    return word
      .replace(/0/g, 'o')
      .replace(/1/g, 'i')
      .replace(/3/g, 'e')
      .replace(/4/g, 'a')
      .replace(/5/g, 's')
      .replace(/7/g, 't')
      .replace(/@/g, 'a')
      .replace(/\$/g, 's');
  });
}

/** Collapses spaced-out letter sequences like "d i s r e g a r d" into words. */
function collapseSpacedLetters(text: string): string {
  return text.replace(/(?:\b[a-zA-Z] )+[a-zA-Z]\b/g, (seq) => {
    const collapsed = seq.replace(/ /g, '');
    return collapsed.length >= 3 ? collapsed : seq;
  });
}

function rot13Decode(text: string): string {
  return text.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

function decodeRot13Segments(text: string): string {
  const out: string[] = [];
  const labeled = text.match(/rot13\s*:\s*([a-zA-Z\s]+)/gi);
  if (labeled) {
    for (const segment of labeled.slice(0, 4)) {
      const payload = segment.replace(/^rot13\s*:\s*/i, '');
      out.push(rot13Decode(payload.trim()));
    }
  }
  return out.join('\n');
}

function decodeHexSegments(text: string): string {
  const out: string[] = [];
  const re = /(?:hex\s*:\s*)([0-9a-fA-F]{16,})/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null && out.length < 4) {
    const hex = match[1];
    if (hex.length % 2 !== 0) continue;
    let decoded = '';
    for (let i = 0; i < hex.length; i += 2) {
      const code = parseInt(hex.slice(i, i + 2), 16);
      if (code < 0x20 || code > 0x7e) {
        decoded = '';
        break;
      }
      decoded += String.fromCharCode(code);
    }
    if (decoded.length >= 8) out.push(decoded);
  }
  return out.join('\n');
}

/**
 * Builds a multi-view haystack for pattern matching: normalized text plus
 * leetspeak/spacing/cyrillic folds and decoded base64/escape/rot13/hex segments.
 */
function buildAnalysisHaystack(payload: string): string {
  let base = normalizeForDetection(payload);
  base = foldCyrillicHomoglyphs(base);
  base = collapseSpacedLetters(base);
  const leet = normalizeLeetspeak(base);

  const views = [base];
  if (leet !== base) views.push(leet);

  const b64 = decodeBase64Segments(base);
  if (b64) views.push(b64);
  const esc = decodeEscapeSequences(base);
  if (esc !== base) views.push(esc);
  const rot = decodeRot13Segments(base);
  if (rot) views.push(rot);
  const hex = decodeHexSegments(base);
  if (hex) views.push(hex);

  if (leet !== base) {
    const leetB64 = decodeBase64Segments(leet);
    if (leetB64) views.push(leetB64);
  }

  return views.join('\n');
}

/**
 * Detects token smuggling attempts by analyzing character distribution and unusual patterns.
 * Attackers often use invisible characters or weird unicode to bypass filters.
 *
 * @param payload - The string payload to analyze (ORIGINAL, pre-normalization)
 * @returns Object containing detection status and score
 */
function detectTokenSmuggling(payload: string): { detected: boolean; score: number } {
  let score = 0;

  const invisibleMatch = payload.match(SMUGGLING_CHARS);
  const invisibleCount = invisibleMatch ? invisibleMatch.length : 0;

  // Invisible characters wedged BETWEEN word characters (or between a word and a
  // space) are an unambiguous smuggling signature - never produced by normal text.
  const interleaved =
    /[A-Za-z0-9][\u200B-\u200D\u2060\uFEFF\u00AD\u180E][A-Za-z0-9]/.test(payload) ||
    /[A-Za-z0-9][\u200B-\u200D\u2060\uFEFF\u00AD\u180E]\s/.test(payload);

  if (interleaved && invisibleCount >= 3) {
    score += 15; // high severity on its own - deliberate obfuscation
  } else if (invisibleCount > 5) {
    score += 10;
  }

  // Excessive use of rare unicode blocks (often used for obfuscation):
  // if > 30% of chars are non-ASCII on a reasonably long payload.
  const nonAscii = payload.replace(/[\x00-\x7F]/g, '').length;
  if (payload.length > 50 && nonAscii / payload.length > 0.3) {
    score += 5;
  }

  return {
    detected: score > 0,
    score,
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

  // Build a normalized "haystack" so obfuscated attacks surface as plain text.
  const haystack = buildAnalysisHaystack(payload);

  // `override: true` marks high-confidence injection categories (override,
  // jailbreak, extraction, exfiltration, delimiter/system manipulation,
  // encoding, multilingual). Pure persona-roleplay and generic chain phrasing
  // are `false`: detected, but not enough on their own to block an LLM route.
  const checks = [
    { patterns: INSTRUCTION_OVERRIDE_PATTERNS, weight: 10, name: 'Instruction Override', override: true },
    { patterns: SYSTEM_PROMPT_MANIPULATION, weight: 15, name: 'System Prompt Manipulation', override: true },
    { patterns: ROLE_MANIPULATION, weight: 7, name: 'Role Manipulation', override: false },
    { patterns: DELIMITER_INJECTION, weight: 15, name: 'Delimiter Injection', override: true },
    { patterns: JAILBREAK_ATTEMPTS, weight: 20, name: 'Jailbreak Attempt', override: true },
    { patterns: PROMPT_EXTRACTION, weight: 8, name: 'Prompt Extraction', override: true },
    { patterns: ENCODING_OBFUSCATION, weight: 6, name: 'Encoding Obfuscation', override: true },
    { patterns: CHAIN_MANIPULATION, weight: 10, name: 'Chain Manipulation', override: true },
    { patterns: MULTILINGUAL_ATTACKS, weight: 15, name: 'Multilingual Attack', override: true },
    { patterns: MALICIOUS_ROLEPLAY, weight: 18, name: 'Jailbreak Attempt', override: true },
    { patterns: JAILBREAK_SUBTYPE, weight: 20, name: 'Jailbreak Attempt', override: true },
    { patterns: SYSTEM_PROMPT_EXTRACTION_SUBTYPE, weight: 15, name: 'Prompt Extraction', override: true },
    { patterns: DATA_EXFIL_SUBTYPE, weight: 20, name: 'Data Exfiltration', override: true },
    { patterns: INSTRUCTION_OVERRIDE_SUBTYPE, weight: 15, name: 'Instruction Override', override: true },
  ];

  for (const check of checks) {
    for (const pattern of check.patterns) {
      const matches = haystack.match(pattern);
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

  // Advanced Checks (run on the ORIGINAL payload - they rely on the obfuscation
  // surface form, which normalization deliberately removes).
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

  const haystack = buildAnalysisHaystack(payload);

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
    if (group.patterns.some(pattern => pattern.test(haystack))) {
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
