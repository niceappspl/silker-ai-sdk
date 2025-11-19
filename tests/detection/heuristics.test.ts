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

    test('should not detect benign HTML', () => {
      expect(detectXssHeuristic("<b>Bold text</b>")).toBe(false);
      expect(detectXssHeuristic("Check out this script for the play")).toBe(false);
    });
  });
});

