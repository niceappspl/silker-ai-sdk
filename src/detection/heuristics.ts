
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
    'SCRIPT', 'IFRAME', 'OBJECT', 'EMBED', 'SVG', 'IMG', 'BODY', 'LINK', 'STYLE', 'META'
]);

const XSS_ATTRIBUTES = new Set([
    'ONERROR', 'ONLOAD', 'ONCLICK', 'ONMOUSEOVER', 'ONFOCUS', 'JAVASCRIPT', 'VBSCRIPT', 'DATA'
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
    if (!input || input.length < 5) return false;

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

    // Always log first 20 tokens on Vercel for debugging
    if (process.env.VERCEL || process.env.SILKER_DEBUG === 'true') {
        console.log('[SQLi Heuristic] Input length:', input.length, 'Tokens:', tokens.slice(0, 20).map(t => t.value).join(' | '));
    }

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
 * Detects XSS using token stream analysis.
 * Looks for dangerous sequences like:
 * - <SCRIPT
 * - JAVASCRIPT:
 * - ONERROR=
 */
export function detectXssHeuristic(input: string): boolean {
    if (!input || input.length < 5) return false;

    const tokens = tokenize(input);

    for (let i = 0; i < tokens.length; i++) {
        const t = tokens[i];
        const next = tokens[i + 1];

        // 1. <TAG
        if (t.value === '<' && next?.type === 'KEYWORD' && XSS_TAGS.has(next.value)) return true;

        // 2. javascript: protocol
        if (t.value === 'JAVASCRIPT' && next?.value === ':') return true;
        if (t.value === 'VBSCRIPT' && next?.value === ':') return true;
        if (t.value === 'DATA' && next?.value === ':') return true;

        // 3. Event handlers: onerror=
        if (XSS_ATTRIBUTES.has(t.value) && next?.value === '=') return true;
    }

    return false;
}
