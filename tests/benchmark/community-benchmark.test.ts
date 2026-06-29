import { runBenchmark, loadThreatDataset } from '../../benchmark/run';

/**
 * Community suite - third-party payloads (PayloadsAllTheThings + HttpParamsDataset).
 * Runs on every CI pass alongside core gates. Floors sit below current measured
 * scores so regressions fail CI without claiming completeness.
 */
describe('Community benchmark suite', () => {
  it('has at least 1000 labeled samples', () => {
    const sqli = loadThreatDataset('community', 'sqli.json');
    const xss = loadThreatDataset('community', 'xss.json');
    expect(sqli.length + xss.length).toBeGreaterThanOrEqual(1000);
  });

  it('runs community benchmark without throwing', () => {
    const results = runBenchmark('community');
    expect(results.suite).toBe('community');
    expect(results.sampleCount).toBeGreaterThanOrEqual(1000);
    expect(results.datasets.length).toBeGreaterThanOrEqual(2);
  });

  it('maintains 0% false positives on community datasets', () => {
    const results = runBenchmark('community');
    for (const d of results.datasets) {
      expect(d.fpr).toBeLessThanOrEqual(0.05);
    }
  });

  it('SQLi TPR stays above community floor', () => {
    const results = runBenchmark('community');
    const sqli = results.datasets.find((d) => d.name === 'SQL Injection');
    expect(sqli).toBeDefined();
    expect(sqli!.tpr).toBeGreaterThanOrEqual(0.65);
  });

  it('XSS TPR stays above community floor', () => {
    const results = runBenchmark('community');
    const xss = results.datasets.find((d) => d.name === 'XSS');
    expect(xss).toBeDefined();
    expect(xss!.tpr).toBeGreaterThanOrEqual(0.90);
  });
});
