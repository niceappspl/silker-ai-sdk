import { runBenchmark, loadThreatDataset } from '../../benchmark/run';

/**
 * Extended suite checks (informational - not CI regression gates).
 * Ensures the transparency benchmark has sufficient size and diversity.
 */
describe('Extended benchmark dataset', () => {
  it('has at least 1000 unique labeled samples', () => {
    const pi = loadThreatDataset('extended', 'prompt-injection.json');
    const sqli = loadThreatDataset('extended', 'sqli.json');
    const xss = loadThreatDataset('extended', 'xss.json');
    const total = pi.length + sqli.length + xss.length;
    expect(total).toBeGreaterThanOrEqual(1000);
  });

  it('prompt injection has diverse attack categories (>= 20)', () => {
    const pi = loadThreatDataset('extended', 'prompt-injection.json');
    const attackCats = new Set(pi.filter((s) => s.label === 'attack').map((s) => s.category));
    expect(attackCats.size).toBeGreaterThanOrEqual(20);
  });

  it('runs extended benchmark without throwing', () => {
    const results = runBenchmark('extended');
    expect(results.suite).toBe('extended');
    expect(results.sampleCount).toBeGreaterThanOrEqual(1000);
    expect(results.datasets).toHaveLength(4);
  });

  it('extended suite maintains 0% false positives on all datasets', () => {
    const results = runBenchmark('extended');
    for (const d of results.datasets) {
      expect(d.fpr).toBe(0);
    }
  });
});
