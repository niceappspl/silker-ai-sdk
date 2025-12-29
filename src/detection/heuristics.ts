
/**
 * Simple heuristic tokenizer for detecting SQLi and XSS without heavy regexes.
 * This reduces false positives by looking for structural patterns rather than just keywords.
 */

export interface Token {
    type: 'KEYWORD' | 'SYMBOL' | 'LITERAL' | 'UNKNOWN';
    value: string;
    position: number;
}

const SQL_KEYWORDS = new Set([
    'SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'FROM', 'WHERE', 'INTO', 'TABLE', 'OR', 'AND', 'EXEC', 'EXECUTE', 'DECLARE', 'CAST', 'CONVERT'
]);

const XSS_TAGS = new Set([
    'SCRIPT', 'IFRAME', 'OBJECT', 'EMBED', 'SVG', 'IMG', 'BODY', 'LINK', 'STYLE', 'META', 'MARQUEE', 'APPLET', 'BASE'
]);

const XSS_ATTRIBUTES = new Set([
    'ONERROR', 'ONLOAD', 'ONCLICK', 'ONMOUSEOVER', 'ONFOCUS', 'JAVASCRIPT', 'VBSCRIPT', 'DATA', 'ONSTART', 'ONSCROLL', 'ONRESIZE'
]);

/**
 * Tokenizes input string into a stream of tokens relevant for security analysis.
 */
function tokenize(input: string): Token[] {
    const tokens: Token[] = [];
    let current = 0;

    // Normalize input for keyword matching
    const normalized = input.toUpperCase();

    while (current < input.length) {
        const char = normalized[current];

        // Skip whitespace
        if (/\s/.test(char)) {
            current++;
            continue;
        }

        // Symbols
        if (/[;'"()=<>*\/\\:-]/.test(char)) {
            // Check for multi-char symbols like --, /*, */
            if (char === '-' && normalized[current + 1] === '-') {
                tokens.push({ type: 'SYMBOL', value: '--', position: current });
                current += 2;
                continue;
            }
            if (char === '/' && normalized[current + 1] === '*') {
                tokens.push({ type: 'SYMBOL', value: '/*', position: current });
                current += 2;
                continue;
            }

            tokens.push({ type: 'SYMBOL', value: char, position: current });
            current++;
            continue;
        }

        // Keywords or Literals
        if (/[A-Z0-9_]/.test(char)) {
            let value = '';
            const start = current;
            while (current < input.length && /[A-Z0-9_]/.test(normalized[current])) {
                value += normalized[current];
                current++;
            }

            if (SQL_KEYWORDS.has(value) || XSS_TAGS.has(value) || XSS_ATTRIBUTES.has(value)) {
                tokens.push({ type: 'KEYWORD', value, position: start });
            } else {
                tokens.push({ type: 'LITERAL', value, position: start });
            }
            continue;
        }

        current++;
    }

    return tokens;
}

/**
 * Detects SQL Injection using token stream analysis.
 * Looks for dangerous sequences like:
 * - UNION SELECT
 * - SELECT ... FROM
 * - ' OR '1'='1
 * - ; DROP TABLE
 */
export function detectSqliHeuristic(input: string): boolean {
    if (!input || input.length < 5) {
        return false;
    }

    // Quick regex-based detection for common SQL injection patterns (fallback)
    const quickPatterns = [
        /' OR '/i,                    // ' OR '
        /' OR 1=/i,                   // ' OR 1=
        /--$/,                        // SQL comment at end
        /UNION.*SELECT/i,             // UNION SELECT
        /; DROP TABLE/i,              // ; DROP TABLE
        /' AND '/i                    // ' AND '
    ];
    
    for (const pattern of quickPatterns) {
        if (pattern.test(input)) {
            return true;
        }
    }

    const tokens = tokenize(input);

    for (let i = 0; i < tokens.length; i++) {
        const t = tokens[i];
        const next = tokens[i + 1];
        const next2 = tokens[i + 2];

        // 1. UNION SELECT
        if (t.value === 'UNION' && next?.value === 'SELECT') return true;

        // 2. SELECT ... FROM (simplified)
        if (t.value === 'SELECT' && next?.value === 'FROM') return true; // unlikely to be adjacent but catches SELECT FROM

        // 3. Comment injection: -- or /*
        if (t.value === '--' || t.value === '/*') return true;

        // 4. Tautology: ' OR '1'='1 or similar patterns
        // Check for OR keyword followed by quotes and equals (common in tautologies)
        if (t.value === 'OR') {
            // Look ahead for patterns like: OR '...' = '...' or OR 1=1
            for (let j = i + 1; j < Math.min(i + 6, tokens.length); j++) {
                if (tokens[j].value === '=') {
                    // Found an equals sign after OR within 6 tokens - likely tautology
                    return true;
                }
            }
        }

        // 5. Quote followed by OR (classic SQLi pattern)
        if (t.value === "'" && next?.value === 'OR') return true;

        // 6. Piggybacked query: ; DROP/INSERT/UPDATE
        if (t.value === ';' && next?.type === 'KEYWORD') {
            if (['DROP', 'INSERT', 'UPDATE', 'DELETE', 'DECLARE', 'EXEC'].includes(next.value)) return true;
        }
    }

    return false;
}

/**
 * Decodes common HTML entities like &#97; or &#x3A; to their character equivalents.
 */
function decodeEntities(input: string): string {
    return input
        .replace(/&#([0-9]{1,3});/gi, (_, dec) => String.fromCharCode(parseInt(dec, 10)))
        .replace(/&#x([0-9a-f]{1,2});/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/&[a-z0-9]+;/gi, (match) => {
            const entities: Record<string, string> = {
                '&lt;': '<', '&gt;': '>', '&quot;': '"', '&apos;': "'", '&amp;': '&',
                '&NewLine;': '\n', '&Tab;': '\t', '&colon;': ':'
            };
            return entities[match] || match;
        });
}

/**
 * Detects XSS using token stream analysis and advanced regex patterns.
 */
export function detectXssHeuristic(input: string): boolean {
    if (!input || input.length < 5) return false;

    // 1. Pre-normalization: Decode HTML entities and lowercase
    const decoded = decodeEntities(input);
    const lower = decoded.toLowerCase();

    // 2. High-confidence regex patterns for obfuscated XSS
    const criticalPatterns = [
        /<script/i,
        /javascript\s*:/i,
        /data\s*:\s*text\/html/i,
        /base64\s*,/i,
        /on\w+\s*=/i, // Any event handler (onerror, onload, etc.)
        /alert\s*\(/i,
        /prompt\s*\(/i,
        /confirm\s*\(/i,
        /eval\s*\(/i,
        /expression\s*\(/i,
        /url\s*\(\s*javascript/i
    ];

    for (const pattern of criticalPatterns) {
        if (pattern.test(decoded)) return true;
    }

    // 3. Catch the specific obfuscated "javascript:" like "j&#97v&#97script"
    // (after decoding entities it becomes "javascript")
    if (lower.includes('javascript:')) return true;

    // 4. Token-based analysis for structural patterns
    const tokens = tokenize(decoded);

    for (let i = 0; i < tokens.length; i++) {
        const t = tokens[i];
        const next = tokens[i + 1];

        // <TAG (including those not in XSS_TAGS but having dangerous attributes)
        if (t.value === '<' && next?.type === 'KEYWORD') {
            const tag = next.value;
            
            // Look ahead for dangerous attributes within this tag
            let j = i + 2;
            let attributeCount = 0;
            while (j < tokens.length && tokens[j].value !== '>') {
                if (tokens[j].type === 'KEYWORD') {
                    attributeCount++;
                    const attr = tokens[j].value;
                    
                    if (XSS_ATTRIBUTES.has(attr)) return true;
                    
                    // Excessive attributes check (obfuscation attempt)
                    if (attributeCount > 15) return true;
                }
                
                // If we see another '<' before '>', it's a new tag, break
                if (tokens[j].value === '<') break;
                j++;
            }

            if (XSS_TAGS.has(tag)) return true;
        }

        // javascript: protocol (standalone or in strings)
        if (t.value === 'JAVASCRIPT' && next?.value === ':') return true;
        if (t.value === 'DATA' && next?.value === ':') return true;

        // Event handlers
        if (XSS_ATTRIBUTES.has(t.value) && next?.value === '=') return true;
    }

    return false;
}
