import { detectSqliHeuristic, detectXssHeuristic } from '../../src/detection/heuristics';

describe('Heuristic Detection', () => {
  describe('SQL Injection', () => {
    test('should detect UNION SELECT', () => {
      expect(detectSqliHeuristic("' UNION SELECT * FROM users")).toBe(true);
    });

    test('should detect comment injection', () => {
      expect(detectSqliHeuristic("admin' --")).toBe(true);
    });

    test('should detect tautology', () => {
      expect(detectSqliHeuristic("' OR '1'='1")).toBe(true);
    });

    test('should not detect benign text', () => {
      expect(detectSqliHeuristic("Hello world")).toBe(false);
      expect(detectSqliHeuristic("Select your option")).toBe(false);
    });

    test('should detect parenthesized / spaced tautologies', () => {
      expect(detectSqliHeuristic("') OR ('a'='a")).toBe(true);
      expect(detectSqliHeuristic("1 OR 1=1")).toBe(true);
      expect(detectSqliHeuristic("x AND 1=1")).toBe(true);
      expect(detectSqliHeuristic("1; DROP TABLE users")).toBe(true);
      expect(detectSqliHeuristic("admin'#")).toBe(true);
    });

    test('should detect ORDER BY / GROUP BY blind probes with trailing comments', () => {
      expect(detectSqliHeuristic("1' ORDER BY 1--")).toBe(true);
      expect(detectSqliHeuristic("1' ORDER BY 10--")).toBe(true);
      expect(detectSqliHeuristic("1' GROUP BY columnnames HAVING 1=1--")).toBe(true);
      expect(detectSqliHeuristic("1')) OR (('1'='1")).toBe(true);
    });

    test('should detect unicode dashes and nested parenthesis tautologies', () => {
      expect(detectSqliHeuristic("' –")).toBe(true);
      expect(detectSqliHeuristic("')) or (('x'))=(('x")).toBe(true);
      expect(detectSqliHeuristic('\")) or ((\"x\"))=((\"x')).toBe(true);
      expect(detectSqliHeuristic("'=\"or'")).toBe(true);
    });

    test('should NOT flag benign text with -- # or or/and (false positives)', () => {
      // Komentarze SQL tylko w kontekście (po cudzysłowie/nawiasie), nie w wolnym tekście.
      expect(detectSqliHeuristic("mid-2024 -- final draft")).toBe(false);
      expect(detectSqliHeuristic("use --flag in cli")).toBe(false);
      expect(detectSqliHeuristic("section # 1 intro")).toBe(false);
      expect(detectSqliHeuristic("color #fff here")).toBe(false);
      // OR/AND blisko key=value (typowe query stringi) - to NIE tautologia.
      expect(detectSqliHeuristic("cats or dogs sort=name")).toBe(false);
      expect(detectSqliHeuristic("search=red or blue&limit=10")).toBe(false);
      expect(detectSqliHeuristic("status=active and verified=true")).toBe(false);
      expect(detectSqliHeuristic("filter=name and age=30")).toBe(false);
    });
  });

  describe('XSS', () => {
    test('should detect script tags', () => {
      expect(detectXssHeuristic("<script>alert(1)</script>")).toBe(true);
    });

    test('should detect javascript protocol', () => {
      expect(detectXssHeuristic("javascript:alert(1)")).toBe(true);
    });

    test('should detect onerror handler', () => {
      expect(detectXssHeuristic("<img src=x onerror=alert(1)>")).toBe(true);
    });

    test('should detect URL encoded and obfuscated XSS evasion payloads', () => {
      expect(detectXssHeuristic("%3Cscript%3Ealert(1)%3C/script%3E")).toBe(true);
      expect(detectXssHeuristic("<<scr\\0ipt/src=http://xss.com/xss.js></script")).toBe(true);
      expect(detectXssHeuristic("<x %6Fnxxx=1")).toBe(true);
      expect(detectXssHeuristic("<math><a xlink:href=\"//jsfiddle.net/t846h/\">click")).toBe(true);
      expect(detectXssHeuristic("href=j&#97v&#97script&#3A;alert(1)")).toBe(true);
    });

    test('should not detect benign HTML', () => {
      expect(detectXssHeuristic("<b>Bold text</b>")).toBe(false);
      expect(detectXssHeuristic("Check out this script for the play")).toBe(false);
      expect(detectXssHeuristic("The <h1> heading should be at the top of the page.")).toBe(false);
    });
  });
});

