import * as fs from 'fs';
import * as path from 'path';
import { detectPromptInjection, shouldBlockPromptInjectionOnLlmRoute } from '../src/detection/promptInjection';
import { detectSqliHeuristic, detectXssHeuristic } from '../src/detection/heuristics';
import { SDK_VERSION } from '../src/version';

export interface Sample {
  text: string;
  label: 'attack' | 'benign';
  category: string;
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

export interface DatasetMetrics {
  name: string;
  policy: string;
  total: number;
  attacks: number;
  benign: number;
  tpr: number;
  fpr: number;
  precision: number;
  confusion: ConfusionMatrix;
  misclassified: Misclassified[];
}

export interface BenchmarkResults {
  version: string;
  generatedAt: string;
  datasets: DatasetMetrics[];
}

type Predict = (text: string) => boolean;

const DATASETS_DIR = path.join(__dirname, 'datasets');

function loadDataset(file: string): Sample[] {
  const raw = fs.readFileSync(path.join(DATASETS_DIR, file), 'utf-8');
  return JSON.parse(raw) as Sample[];
}

/** Rounds to 4 decimals, guarding against division by zero (returns 0). */
function ratio(numerator: number, denominator: number): number {
  if (denominator === 0) return 0;
  return Math.round((numerator / denominator) * 10000) / 10000;
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

  return {
    name,
    policy,
    total: samples.length,
    attacks,
    benign,
    tpr: ratio(confusion.truePositives, attacks),
    fpr: ratio(confusion.falsePositives, benign),
    precision: ratio(confusion.truePositives, confusion.truePositives + confusion.falsePositives),
    confusion,
    misclassified,
  };
}

/**
 * Prompt injection blocking policy for LLM routes (mirrors isAnomaly() in
 * src/detection/anomaly.ts): block on medium+ severity, or a low-severity match
 * that carries a high-confidence override signal. Pure persona-roleplay passes.
 */
const predictPromptInjectionLlm: Predict = (text) =>
  shouldBlockPromptInjectionOnLlmRoute(detectPromptInjection(text));

/**
 * Prompt injection blocking policy for non-LLM routes: block only when detected
 * AND severity is high or critical (mirrors isAnomaly() in src/detection/anomaly.ts).
 */
const predictPromptInjectionGeneric: Predict = (text) => {
  const r = detectPromptInjection(text);
  return r.detected && (r.severity === 'high' || r.severity === 'critical');
};

/**
 * Runs the full detection benchmark across all datasets and policies.
 * Pure function: loads datasets, runs detectors, returns metrics (no side effects).
 */
export function runBenchmark(): BenchmarkResults {
  const promptInjection = loadDataset('prompt-injection.json');
  const sqli = loadDataset('sqli.json');
  const xss = loadDataset('xss.json');

  const datasets: DatasetMetrics[] = [
    evaluate('Prompt Injection', 'llm-route (medium+ or override signal)', promptInjection, predictPromptInjectionLlm),
    evaluate('Prompt Injection', 'non-llm-route (high/critical)', promptInjection, predictPromptInjectionGeneric),
    evaluate('SQL Injection', 'block on detection', sqli, detectSqliHeuristic),
    evaluate('XSS', 'block on detection', xss, detectXssHeuristic),
  ];

  return {
    version: SDK_VERSION,
    generatedAt: new Date().toISOString(),
    datasets,
  };
}

function pct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function printConsole(results: BenchmarkResults): void {
  console.log(`\nSilker AI detection benchmark - @silker-ai/agent v${results.version}`);
  console.log(`Generated: ${results.generatedAt}\n`);

  const table = results.datasets.map((d) => ({
    Dataset: d.name,
    Policy: d.policy,
    N: d.total,
    TPR: pct(d.tpr),
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
    for (const m of d.misclassified) {
      const kind = m.expected === 'attack' ? 'FALSE NEGATIVE' : 'FALSE POSITIVE';
      const snippet = m.text.length > 70 ? `${m.text.slice(0, 70)}…` : m.text;
      console.log(`  [${kind}] (${m.category}) ${JSON.stringify(snippet)}`);
    }
  }
}

function toMarkdown(results: BenchmarkResults): string {
  const date = results.generatedAt.slice(0, 10);
  const lines: string[] = [];
  lines.push(`# Silker AI Detection Benchmark Results`);
  lines.push('');
  lines.push(`- **Package:** \`@silker-ai/agent\``);
  lines.push(`- **Version:** \`${results.version}\``);
  lines.push(`- **Date:** ${date}`);
  lines.push(`- **Generated:** ${results.generatedAt}`);
  lines.push('');
  lines.push(`## Summary`);
  lines.push('');
  lines.push(`| Dataset | Policy | N | TPR (detection rate) | FPR | Precision | TP | FN | FP | TN |`);
  lines.push(`| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |`);
  for (const d of results.datasets) {
    lines.push(
      `| ${d.name} | ${d.policy} | ${d.total} | ${pct(d.tpr)} | ${pct(d.fpr)} | ${pct(d.precision)} | ` +
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
    for (const m of d.misclassified) {
      const kind = m.expected === 'attack' ? 'FN' : 'FP';
      const snippet = m.text.replace(/\|/g, '\\|').replace(/\n/g, ' ').slice(0, 100);
      lines.push(`| ${kind} | ${m.category} | \`${snippet}\` |`);
    }
  }
  lines.push('');
  return lines.join('\n');
}

/** Writes results.json and RESULTS.md next to this runner. */
export function writeArtifacts(results: BenchmarkResults): void {
  fs.writeFileSync(path.join(__dirname, 'results.json'), JSON.stringify(results, null, 2) + '\n', 'utf-8');
  fs.writeFileSync(path.join(__dirname, 'RESULTS.md'), toMarkdown(results), 'utf-8');
}

if (require.main === module) {
  const results = runBenchmark();
  printConsole(results);
  writeArtifacts(results);
  console.log(`\nWrote benchmark/results.json and benchmark/RESULTS.md`);
}
