# Silker AI Detection Benchmark

Reproducible benchmark measuring **detection rate (TPR)**, **false-positive rate (FPR)**,
and **macro-average TPR per category** for the SDK heuristic detectors.

## Two suites

| Suite | Purpose | Size | CI gate |
| --- | --- | ---: | --- |
| **core** | Fast regression gate on every PR | ~210 samples | yes (`quality-gate.test.ts`) |
| **extended** | Transparency / release honesty | ~630+ samples | no (informational) |

Extended = **core + additions** (`datasets/extended/additions/`), deduped by exact text at load time.

```
benchmark/datasets/
  core/                    # hand-curated baseline (CI)
    prompt-injection.json
    sqli.json
    xss.json
  extended/additions/      # generated + curated expansions
    prompt-injection.json
    sqli.json
    xss.json
```

Regenerate additions:

```bash
npm run benchmark:generate
```

## Commands

```bash
npm run benchmark              # core suite → results.json, RESULTS.md
npm run benchmark:extended     # extended suite → results-extended.json
npm run benchmark:all          # both
```

## Current results (v1.5.2)

### Core suite (~210 samples) - CI gate

| Dataset | Policy | TPR | FPR |
| --- | --- | ---: | ---: |
| Prompt Injection | LLM-route | 100.0% | 0.0% |
| Prompt Injection | non-LLM-route | 100.0% | 0.0% |
| SQL Injection | block on detection | 100.0% | 0.0% |
| XSS | block on detection | 100.0% | 0.0% |

### Extended suite (~1012 samples) - transparency

| Dataset | Policy | TPR | Macro TPR | FPR |
| --- | --- | ---: | ---: | ---: |
| Prompt Injection | LLM-route | 100.0% | 100.0% | 0.0% |
| Prompt Injection | non-LLM-route | 97.6% | 97.8% | 0.0% |
| SQL Injection | block on detection | 96.9% | 97.1% | 0.0% |
| XSS | block on detection | 100.0% | 100.0% | 0.0% |

Extended = core + 802 unique additions across 30+ PI categories, 13 SQLi categories,
11 XSS categories. See [CATEGORIES.md](./CATEGORIES.md) for what each category probes.

## Detectors

| Detector | API | Dataset file(s) |
| --- | --- | --- |
| Prompt injection | `detectPromptInjection()` | `prompt-injection.json` |
| SQL injection | `detectSqliHeuristic()` | `sqli.json` |
| XSS | `detectXssHeuristic()` | `xss.json` |

### Prompt-injection policies (mirrors `isAnomaly()`)

- **LLM-route** - `shouldBlockPromptInjectionOnLlmRoute()`: medium+ severity, or low + override signal
- **non-LLM-route** - high/critical only

## Sample schema

```json
{ "text": "...", "label": "attack" | "benign", "category": "...", "source": "optional" }
```

## CI regression gate

`tests/benchmark/quality-gate.test.ts` runs the **core** suite only. Bars sit slightly
below measured core values so regressions fail CI without blocking on extended gaps.

## Caveats

- Heuristic detection, not ML/semantic.
- Core = regression direction; extended = honest coverage map.
- Do not add samples solely to inflate metrics - stratify by category instead.
