
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
    'SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'FROM', 'WHERE', 'INTO', 'TABLE', 'OR', 'AND', 'EXEC', 'EXECUTE', 'DECLARE', 'CAST', 'CONVERT', 'ORDER', 'GROUP', 'BY', 'HAVING'
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

        // MySQL hash comment: # starts a line comment
        if (char === '#') {
            tokens.push({ type: 'SYMBOL', value: '#', position: current });
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
    if (!input) {
        return false;
    }

    // Quick regex-based detection for common SQL injection patterns (fallback).
    // Runs regardless of length: every pattern here requires SQL-specific
    // structure (keyword + operator combos, unique function names), so short
    // benign strings (a bare "'", "=", single symbol) never match - only the
    // tokenizer pass below is gated by length to avoid noise on short input.
    // Comment markers (--, #, /*) are matched ONLY in SQL context (right after a
    // quote, closing paren or semicolon) to avoid false positives on benign
    // text like "mid-2024 -- note", "use --flag" or "section # 1".
    const quickPatterns = [
        /' OR '/i,                    // ' OR '
        /" OR "/i,                    // " OR " (double-quote variant)
        /' OR \d+\s*=/i,              // ' OR 1= (tautology, allows spaces)
        /['");]\s*(?:--|[–—])/,       // line comment after quote/paren/semicolon (including unicode dashes)
        /['");]\s*#/,                 // MySQL hash comment after quote/paren/semicolon
        /['")]\s*\/\*/,               // block comment after quote/paren
        /'[^']*\bORDER\s+BY\b/i,      // quote-break column enumeration (1' ORDER BY 1--)
        /'[^']*\bGROUP\s+BY\b/i,      // quote-break GROUP BY / HAVING probes
        /\bORDER\s+BY\s+\d+\b/,       // ORDER BY N (column-count enumeration probe)
        /\bORDER\s+BY\b[\s\S]{0,60}\b(SLEEP|BENCHMARK)\s*\(/i, // ORDER BY … SLEEP()/BENCHMARK() (time-based)
        /\bGROUP\s+BY\b.+\bHAVING\b/i, // GROUP BY … HAVING tautology probes
        /\bHAVING\s+\d+\s*=\s*\d+/i,  // standalone HAVING 1=1 / HAVING 1=0
        /UNION.*SELECT/i,             // UNION SELECT
        /\bDROP\s+(TABLE|FUNCTION|PROCEDURE|DATABASE|INDEX|VIEW)\b/i, // DROP TABLE/FUNCTION/…
        /' AND '/i,                   // ' AND '
        /" AND "/i,                   // " AND " (double-quote variant)
        /' AND \d/i,                  // ' AND 1= tautology
        /\b(OR|AND)\s+\d+\s*=\s*\d+/i, // bare numeric boolean probe: OR 1=0 / AND 1=1
        /\b(OR|AND)\s+[a-zA-Z]\s*=\s*[a-zA-Z]\b/i, // bare identifier probe: OR x=y
        /\b(OR|AND)\s+[\(\s\'\"]*([a-zA-Z0-9_]+)[\)\s\'\"]*\s*=\s*[\(\s\'\"]*\2\b/i, // nested paren tautology: )) or (('x'))=(('x
        /['"]\s*=\s*['"]or['"]?/i,    // assignment tautology probe: '="or'
        /\bor\s+true\b/i,             // or true / or true--
        /\blike\s+'%+'/i,             // LIKE '%' always-true wildcard bypass
        /sleep\s*\(\s*\d/i,           // SLEEP(5), pg_SLEEP(5) - time-based blind
        /\bbenchmark\s*\(\s*\d+\s*,/i, // MySQL BENCHMARK(count, expr) - time-based blind
        /waitfor\s+delay\s+'/i,       // MSSQL WAITFOR DELAY '...' - time-based blind
        /\brandomblob\s*\(/i,         // SQLite RANDOMBLOB() - time-based blind
        /\brlike\s*\(/i,              // MySQL RLIKE(...) blind probe
        /@@version\b/i,               // MySQL/MSSQL system variable fingerprinting
        /\binformation_schema\b/i,    // metadata schema enumeration
        /\b(cast|convert)\s*\([^)]*\bselect\b/i, // CAST/CONVERT wrapping a nested SELECT
        /\bcase\s+when\b[\s\S]{0,60}\bthen\b/i,  // CASE WHEN … THEN conditional probe
        /(?:char|chr)\s*\(\s*\d+\s*\)\s*(?:\+|\|\|)\s*(?:char|chr)\s*\(\s*\d+\s*\)/i, // CHAR()/CHR() concatenation obfuscation
    ];

    for (const pattern of quickPatterns) {
        if (pattern.test(input)) {
            return true;
        }
    }

    if (input.length < 5) {
        return false;
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

        // 3. Block comment injection (/* */). Line comments (--) and MySQL hash (#)
        // are handled contextually by the quick patterns above to avoid FPs on
        // free text that happens to contain "--" or "#".
        if (t.value === '/*') return true;

        // 4. Tautology: OR/AND ... <operand> = <operand> with IDENTICAL operands
        // (e.g. 1=1, 'a'='a, (1=1)). We scan a short window after OR/AND, find the
        // equality and compare the operands flanking it (skipping quotes/parens).
        // Only IDENTICAL operands flag, so benign "key=value" pairs near "or"/"and"
        // (e.g. "active and verified=true", "red or blue&sort=name") are NOT flagged.
        if (t.value === 'OR' || t.value === 'AND') {
            const windowEnd = Math.min(i + 24, tokens.length);
            let eqIndex = -1;
            for (let j = i + 1; j < windowEnd; j++) {
                if (tokens[j].value === '=') {
                    eqIndex = j;
                    break;
                }
            }
            if (eqIndex > i) {
                const isOperand = (tk?: Token) =>
                    !!tk && (tk.type === 'LITERAL' || tk.type === 'KEYWORD');
                let before: Token | undefined;
                for (let j = eqIndex - 1; j > i; j--) {
                    if (isOperand(tokens[j])) { before = tokens[j]; break; }
                }
                let after: Token | undefined;
                for (let j = eqIndex + 1; j < windowEnd; j++) {
                    if (isOperand(tokens[j])) { after = tokens[j]; break; }
                }
                if (before && after && before.value === after.value) {
                    return true;
                }
            }
        }

        // 5. Quote followed by OR or AND (classic SQLi pattern)
        if (t.value === "'" && (next?.value === 'OR' || next?.value === 'AND')) return true;

        // 6. Piggybacked query: ; DROP/INSERT/UPDATE
        if (t.value === ';' && next?.type === 'KEYWORD') {
            if (['DROP', 'INSERT', 'UPDATE', 'DELETE', 'DECLARE', 'EXEC'].includes(next.value)) return true;
        }
    }

    return false;
}

/**
 * Decodes common URL encoding (e.g. %3C, %2F, %22, %6F) up to 2 passes.
 */
function decodeUrl(input: string): string {
    let prev = input;
    for (let pass = 0; pass < 2; pass++) {
        try {
            const next = decodeURIComponent(prev.replace(/\+/g, ' '));
            if (next === prev) break;
            prev = next;
        } catch {
            const next = prev.replace(/%([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
            if (next === prev) break;
            prev = next;
        }
    }
    return prev;
}

/**
 * Decodes common HTML entities like &#97; or &#x3A; to their character equivalents.
 */
function decodeEntities(input: string): string {
    return input
        .replace(/&#([0-9]{1,3});?/gi, (_, dec) => String.fromCharCode(parseInt(dec, 10)))
        .replace(/&#x([0-9a-f]{1,2});?/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
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

    // 1. Pre-normalization: Strip null bytes, decode URL, decode HTML entities and lowercase
    let cleaned = input.replace(/\\0|\0|\x00/g, '');
    cleaned = decodeUrl(cleaned);
    const decoded = decodeEntities(cleaned);
    const lower = decoded.toLowerCase();

    // 2. High-confidence regex patterns for obfuscated XSS
    const criticalPatterns = [
        /<script/i,
        /javascript\s*:/i,
        /data\s*:\s*text\/html/i,
        /base64\s*,/i,
        /on\w+\s*=/i, // Any event handler (onerror, onload, etc.)
        /xlink:href\s*=/i, // SVG/MathML namespace execution
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
