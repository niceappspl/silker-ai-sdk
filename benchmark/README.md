# Silker AI Detection Benchmark

A reproducible benchmark that measures the **detection rate (TPR)** and **false
positive rate (FPR)** of the SDK's heuristic detectors against curated, labeled
datasets. It exists so detection quality can be published as proof of quality
and so CI catches regressions over time.

## What it measures

| Detector | Public API | Datasets |
| --- | --- | --- |
| Prompt injection | `detectPromptInjection()` from `src/detection/promptInjection.ts` | `datasets/prompt-injection.json` |
| SQL injection | `detectSqliHeuristic()` from `src/detection/heuristics.ts` | `datasets/sqli.json` |
| XSS | `detectXssHeuristic()` from `src/detection/heuristics.ts` | `datasets/xss.json` |

### Prompt-injection: two production policies

The benchmark reports prompt injection under **both** blocking policies used in
production (`isAnomaly()` in `src/detection/anomaly.ts`):

- **LLM-route policy** - blocks on **any** detection (`result.detected === true`).
  Applied to LLM endpoints (`/api/chat`, OpenAI/Anthropic hosts, …). Aggressive:
  maximizes recall at the cost of false positives.
- **Non-LLM-route policy** - blocks only when `detected && severity ∈ {high, critical}`.
  Applied to generic endpoints. Conservative: minimizes false positives.

## Dataset schema

Each entry is `{ "text": string, "label": "attack" | "benign", "category": string }`.

- `prompt-injection.json` - ~60 attack payloads (instruction override, system
  prompt extraction, DAN/jailbreak, role manipulation, delimiter injection like
  `[INST]` / `<|system|>`, encoding obfuscation, multilingual, invisible-unicode
  token smuggling, obfuscated keywords) + ~45 benign-but-risky samples (legit
  roleplay UX like "act as a translator", innocent mentions of "system prompt",
  normal questions, long benign text).
- `sqli.json` / `xss.json` - ~20 attacks + ~20 benign each, where benign samples
  deliberately contain SQL keywords (`select the best option from the list`) or
  HTML-ish text (`use the <strong> tag`) to probe false positives.

Datasets were authored from well-known public attack patterns. They are a
**baseline**, not an adversarial-robustness corpus.

## How to run

```bash
npm run benchmark
```

This:

1. Loads the datasets.
2. Runs each sample through the relevant detector(s) under each policy.
3. Computes per-dataset TPR, FPR, precision, a confusion matrix, and the list of
   misclassified samples.
4. Prints a console table and writes `benchmark/results.json` and
   `benchmark/RESULTS.md` (full table + misclassifications, dated and tagged with
   the package version from `src/version.ts`).

The runner uses `ts-node` with `tsconfig.benchmark.json` (transpile-only).

## Metrics

- **TPR (detection rate)** = `TP / (TP + FN)` - share of attacks caught.
- **FPR** = `FP / (FP + TN)` - share of benign samples wrongly flagged.
- **Precision** = `TP / (TP + FP)` - share of flags that were real attacks.

## Current results summary (v1.3.2)

| Dataset | Policy | TPR | FPR | Precision |
| --- | --- | ---: | ---: | ---: |
| Prompt Injection | LLM-route (any detection) | 98.3% | 24.4% | 84.1% |
| Prompt Injection | non-LLM-route (high/critical) | 76.3% | 2.2% | 97.8% |
| SQL Injection | block on detection | 100.0% | 0.0% | 100.0% |
| XSS | block on detection | 100.0% | 0.0% | 100.0% |

See `RESULTS.md` for the per-sample misclassification breakdown.

### Observations / detector weaknesses

- **LLM-route FPR is high (~24%)**: low-severity role phrases that are legitimate
  LLM UX ("act as …", "pretend you are …", "simulate a …", "roleplay as …",
  "imagine you are …") are flagged because the LLM policy blocks on *any*
  detection. This is a recall-vs-precision trade-off, not a bug.
- **Non-LLM-route misses obfuscated attacks (TPR ~76%)**: token smuggling
  (severity medium), encoding obfuscation (low), multilingual (medium), and
  "skip … instructions" (medium) score below the high/critical threshold and so
  pass the conservative policy. They *are* caught under the LLM policy.
- **Over-eager pattern**: the benign phrase "the new instructions for assembling
  the furniture …" matches `new (instructions|role|mode|system)` at high
  severity, producing a false positive under **both** policies.
- **SQLi / XSS**: perfect on this baseline dataset, but the dataset is small and
  not adversarial.

## CI regression gate

`tests/benchmark/quality-gate.test.ts` runs the benchmark programmatically and
asserts minimum bars (set slightly below the values above) so regressions fail
CI. The bars are honest to the measured numbers, not the aspirational targets -
in particular the LLM-route FPR gate reflects the real ~24% and is not forced to
≤10%.

## Caveats

- Detection is **heuristic** (regex/token-stream), not ML/semantic. Novel or
  heavily obfuscated payloads can evade it.
- The dataset is a **baseline** for measuring direction and regressions, **not**
  proof of adversarial robustness.
- Results depend on the dataset; do not add samples to inflate metrics.
