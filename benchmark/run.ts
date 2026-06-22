import * as fs from 'fs';
import * as path from 'path';
import { detectPromptInjection, shouldBlockPromptInjectionOnLlmRoute } from '../src/detection/promptInjection';
import { detectSqliHeuristic, detectXssHeuristic } from '../src/detection/heuristics';
import { SDK_VERSION } from '../src/version';

export type BenchmarkSuite = 'core' | 'extended';

export interface Sample {
  text: string;
  label: 'attack' | 'benign';
  category: string;
  source?: string;
}

export interface ConfusionMatrix {
  truePositives: number;
  falseNegatives: number;
  falsePositives: number;
  trueNegatives: number;
}

export interface Misclassified {
  text: string;
  category: string;
  expected: 'attack' | 'benign';
  predicted: 'attack' | 'benign';
}

export interface CategoryMetrics {
  category: string;
  attacks: number;
  benign: number;
  tpr: number;
  fpr: number;
}

export interface DatasetMetrics {
  name: string;
  policy: string;
  total: number;
  attacks: number;
  benign: number;
  tpr: number;
  fpr: number;
  precision: number;
  macroTpr: number;
  confusion: ConfusionMatrix;
  misclassified: Misclassified[];
  byCategory: CategoryMetrics[];
}

export interface BenchmarkResults {
  suite: BenchmarkSuite;
  version: string;
  generatedAt: string;
  sampleCount: number;
  datasets: DatasetMetrics[];
}

type Predict = (text: string) => boolean;

const DATASETS_ROOT = path.join(__dirname, 'datasets');
const THREAT_FILES = ['prompt-injection.json', 'sqli.json', 'xss.json'] as const;

function readJson(filePath: string): Sample[] {
  if (!fs.existsSync(filePath)) return [];
  return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as Sample[];
}

/** Deduplicate by exact text; first occurrence wins (core before additions). */
export function dedupeSamples(samples: Sample[]): Sample[] {
  const seen = new Set<string>();
  const out: Sample[] = [];
  for (const s of samples) {
    if (seen.has(s.text)) continue;
    seen.add(s.text);
    out.push(s);
  }
  return out;
}

export function loadThreatDataset(suite: BenchmarkSuite, file: string): Sample[] {
  const core = readJson(path.join(DATASETS_ROOT, 'core', file));
  if (suite === 'core') return dedupeSamples(core);

  const additions = readJson(path.join(DATASETS_ROOT, 'extended', 'additions', file));
  return dedupeSamples([...core, ...additions]);
}

/** Rounds to 4 decimals, guarding against division by zero (returns 0). */
function ratio(numerator: number, denominator: number): number {
  if (denominator === 0) return 0;
  return Math.round((numerator / denominator) * 10000) / 10000;
}

function categoryBreakdown(samples: Sample[], predict: Predict): CategoryMetrics[] {
  const byCat = new Map<string, { tp: number; fn: number; fp: number; tn: number }>();

  for (const sample of samples) {
    const flagged = predict(sample.text);
    const bucket = byCat.get(sample.category) ?? { tp: 0, fn: 0, fp: 0, tn: 0 };
    if (sample.label === 'attack') {
      if (flagged) bucket.tp++;
      else bucket.fn++;
    } else if (flagged) bucket.fp++;
    else bucket.tn++;
    byCat.set(sample.category, bucket);
  }

  return [...byCat.entries()]
    .map(([category, c]) => ({
      category,
      attacks: c.tp + c.fn,
      benign: c.fp + c.tn,
      tpr: ratio(c.tp, c.tp + c.fn),
      fpr: ratio(c.fp, c.fp + c.tn),
    }))
    .sort((a, b) => a.category.localeCompare(b.category));
}

function evaluate(name: string, policy: string, samples: Sample[], predict: Predict): DatasetMetrics {
  const confusion: ConfusionMatrix = {
    truePositives: 0,
    falseNegatives: 0,
    falsePositives: 0,
    trueNegatives: 0,
  };
  const misclassified: Misclassified[] = [];

  for (const sample of samples) {
    const flagged = predict(sample.text);
    const predicted: 'attack' | 'benign' = flagged ? 'attack' : 'benign';

    if (sample.label === 'attack') {
      if (flagged) confusion.truePositives++;
      else confusion.falseNegatives++;
    } else {
      if (flagged) confusion.falsePositives++;
      else confusion.trueNegatives++;
    }

    if (predicted !== sample.label) {
      misclassified.push({
        text: sample.text,
        category: sample.category,
        expected: sample.label,
        predicted,
      });
    }
  }

  const attacks = confusion.truePositives + confusion.falseNegatives;
  const benign = confusion.falsePositives + confusion.trueNegatives;
  const byCategory = categoryBreakdown(samples, predict);
  const attackCategories = byCategory.filter((c) => c.attacks > 0);
  const macroTpr =
    attackCategories.length === 0
      ? 0
      : ratio(
          attackCategories.reduce((sum, c) => sum + c.tpr, 0),
          attackCategories.length
        );

  return {
    name,
    policy,
    total: samples.length,
    attacks,
    benign,
    tpr: ratio(confusion.truePositives, attacks),
    fpr: ratio(confusion.falsePositives, benign),
    precision: ratio(confusion.truePositives, confusion.truePositives + confusion.falsePositives),
    macroTpr,
    confusion,
    misclassified,
    byCategory,
  };
}

const predictPromptInjectionLlm: Predict = (text) =>
  shouldBlockPromptInjectionOnLlmRoute(detectPromptInjection(text));

const predictPromptInjectionGeneric: Predict = (text) => {
  const r = detectPromptInjection(text);
  return r.detected && (r.severity === 'high' || r.severity === 'critical');
};

/**
 * Runs the detection benchmark for the given suite.
 * - core: CI regression gate (~210 samples)
 * - extended: core + additions (~640+ samples, transparency / release)
 */
export function runBenchmark(suite: BenchmarkSuite = 'core'): BenchmarkResults {
  const promptInjection = loadThreatDataset(suite, 'prompt-injection.json');
  const sqli = loadThreatDataset(suite, 'sqli.json');
  const xss = loadThreatDataset(suite, 'xss.json');

  const datasets: DatasetMetrics[] = [
    evaluate('Prompt Injection', 'llm-route (medium+ or override signal)', promptInjection, predictPromptInjectionLlm),
    evaluate('Prompt Injection', 'non-llm-route (high/critical)', promptInjection, predictPromptInjectionGeneric),
    evaluate('SQL Injection', 'block on detection', sqli, detectSqliHeuristic),
    evaluate('XSS', 'block on detection', xss, detectXssHeuristic),
  ];

  return {
    suite,
    version: SDK_VERSION,
    generatedAt: new Date().toISOString(),
    sampleCount: promptInjection.length + sqli.length + xss.length,
    datasets,
  };
}

function pct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function printConsole(results: BenchmarkResults): void {
  console.log(`\nSilker AI detection benchmark [${results.suite}] - @silker-ai/agent v${results.version}`);
  console.log(`Generated: ${results.generatedAt} · ${results.sampleCount} labeled samples\n`);

  const table = results.datasets.map((d) => ({
    Dataset: d.name,
    Policy: d.policy,
    N: d.total,
    TPR: pct(d.tpr),
    'Macro TPR': pct(d.macroTpr),
    FPR: pct(d.fpr),
    Precision: pct(d.precision),
    TP: d.confusion.truePositives,
    FN: d.confusion.falseNegatives,
    FP: d.confusion.falsePositives,
    TN: d.confusion.trueNegatives,
  }));
  console.table(table);

  for (const d of results.datasets) {
    if (d.misclassified.length === 0) continue;
    console.log(`\nMisclassified - ${d.name} [${d.policy}] (${d.misclassified.length}):`);
    for (const m of d.misclassified.slice(0, 25)) {
      const kind = m.expected === 'attack' ? 'FALSE NEGATIVE' : 'FALSE POSITIVE';
      const snippet = m.text.length > 70 ? `${m.text.slice(0, 70)}…` : m.text;
      console.log(`  [${kind}] (${m.category}) ${JSON.stringify(snippet)}`);
    }
    if (d.misclassified.length > 25) {
      console.log(`  … and ${d.misclassified.length - 25} more (see results JSON)`);
    }
  }
}

function toMarkdown(results: BenchmarkResults): string {
  const date = results.generatedAt.slice(0, 10);
  const lines: string[] = [];
  lines.push(`# Silker AI Detection Benchmark Results`);
  lines.push('');
  lines.push(`- **Suite:** \`${results.suite}\``);
  lines.push(`- **Package:** \`@silker-ai/agent\``);
  lines.push(`- **Version:** \`${results.version}\``);
  lines.push(`- **Date:** ${date}`);
  lines.push(`- **Samples:** ${results.sampleCount}`);
  lines.push(`- **Generated:** ${results.generatedAt}`);
  lines.push('');
  lines.push(`## Summary`);
  lines.push('');
  lines.push(`| Dataset | Policy | N | TPR | Macro TPR | FPR | Precision | TP | FN | FP | TN |`);
  lines.push(`| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |`);
  for (const d of results.datasets) {
    lines.push(
      `| ${d.name} | ${d.policy} | ${d.total} | ${pct(d.tpr)} | ${pct(d.macroTpr)} | ${pct(d.fpr)} | ${pct(d.precision)} | ` +
        `${d.confusion.truePositives} | ${d.confusion.falseNegatives} | ${d.confusion.falsePositives} | ${d.confusion.trueNegatives} |`
    );
  }
  lines.push('');
  lines.push(`## Misclassified samples`);
  for (const d of results.datasets) {
    lines.push('');
    lines.push(`### ${d.name} - ${d.policy}`);
    if (d.misclassified.length === 0) {
      lines.push('');
      lines.push(`_No misclassifications._`);
      continue;
    }
    lines.push('');
    lines.push(`| Type | Category | Sample |`);
    lines.push(`| --- | --- | --- |`);
    for (const m of d.misclassified.slice(0, 50)) {
      const kind = m.expected === 'attack' ? 'FN' : 'FP';
      const snippet = m.text.replace(/\|/g, '\\|').replace(/\n/g, ' ').slice(0, 100);
      lines.push(`| ${kind} | ${m.category} | \`${snippet}\` |`);
    }
    if (d.misclassified.length > 50) {
      lines.push('');
      lines.push(`_… and ${d.misclassified.length - 50} more (see results JSON)._`);
    }
  }
  lines.push('');
  return lines.join('\n');
}

/** Writes suite-specific results next to this runner. */
export function writeArtifacts(results: BenchmarkResults): void {
  const suffix = results.suite === 'core' ? '' : `-${results.suite}`;
  fs.writeFileSync(
    path.join(__dirname, `results${suffix}.json`),
    JSON.stringify(results, null, 2) + '\n',
    'utf-8'
  );
  fs.writeFileSync(path.join(__dirname, `RESULTS${suffix}.md`), toMarkdown(results), 'utf-8');

  // Keep legacy paths for core suite (CI / docs links).
  if (results.suite === 'core') {
    fs.writeFileSync(path.join(__dirname, 'results.json'), JSON.stringify(results, null, 2) + '\n', 'utf-8');
    fs.writeFileSync(path.join(__dirname, 'RESULTS.md'), toMarkdown(results), 'utf-8');
  }
}

function parseSuiteArg(): BenchmarkSuite {
  const arg = process.argv.find((a) => a.startsWith('--suite='));
  const value = arg?.split('=')[1] ?? process.env.BENCHMARK_SUITE ?? 'core';
  if (value === 'core' || value === 'extended') return value;
  throw new Error(`Unknown suite "${value}". Use --suite=core or --suite=extended`);
}

if (require.main === module) {
  const suite = parseSuiteArg();
  const results = runBenchmark(suite);
  printConsole(results);
  writeArtifacts(results);
  const suffix = suite === 'core' ? '' : `-${suite}`;
  console.log(`\nWrote benchmark/results${suffix}.json and benchmark/RESULTS${suffix}.md`);
}
