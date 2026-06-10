import { runBenchmark, BenchmarkResults, DatasetMetrics } from '../../benchmark/run';

/**
 * Regression gates for the detection benchmark.
 *
 * Bars are set slightly below the values actually achieved by v1.3.3 so the
 * suite passes today but fails if a future change degrades detection rate (TPR)
 * or inflates the false positive rate (FPR).
 *
 * v1.3.3 replaced the LLM-route "block on any detection" policy with a precise
 * one (block on medium+ severity, or a low-severity match carrying a
 * high-confidence override signal). Pure persona-roleplay UX phrases like
 * "act as a translator" now pass, dropping the LLM-route FPR from ~24% to ~0%
 * while keeping detection rate (TPR) at ~95%.
 */
describe('Detection benchmark quality gates', () => {
  let results: BenchmarkResults;

  beforeAll(() => {
    results = runBenchmark();
  });

  const find = (name: string, policyPrefix: string): DatasetMetrics => {
    const match = results.datasets.find(
      (d) => d.name === name && d.policy.startsWith(policyPrefix)
    );
    if (!match) {
      throw new Error(`Dataset not found: ${name} / ${policyPrefix}`);
    }
    return match;
  };

  describe('Prompt Injection - LLM-route policy (medium+ or override signal)', () => {
    it('detection rate (TPR) stays high', () => {
      const m = find('Prompt Injection', 'llm-route');
      expect(m.tpr).toBeGreaterThanOrEqual(0.93);
    });

    it('false positive rate stays low', () => {
      const m = find('Prompt Injection', 'llm-route');
      expect(m.fpr).toBeLessThanOrEqual(0.05);
    });
  });

  describe('Prompt Injection - non-LLM-route policy (high/critical only)', () => {
    it('detection rate (TPR) stays high', () => {
      const m = find('Prompt Injection', 'non-llm-route');
      expect(m.tpr).toBeGreaterThanOrEqual(0.72);
    });

    it('false positive rate stays low', () => {
      const m = find('Prompt Injection', 'non-llm-route');
      expect(m.fpr).toBeLessThanOrEqual(0.02);
    });
  });

  describe('SQL Injection', () => {
    it('detection rate (TPR) stays high', () => {
      const m = find('SQL Injection', 'block');
      expect(m.tpr).toBeGreaterThanOrEqual(0.95);
    });

    it('false positive rate stays low', () => {
      const m = find('SQL Injection', 'block');
      expect(m.fpr).toBeLessThanOrEqual(0.05);
    });
  });

  describe('XSS', () => {
    it('detection rate (TPR) stays high', () => {
      const m = find('XSS', 'block');
      expect(m.tpr).toBeGreaterThanOrEqual(0.95);
    });

    it('false positive rate stays low', () => {
      const m = find('XSS', 'block');
      expect(m.fpr).toBeLessThanOrEqual(0.05);
    });
  });
});
