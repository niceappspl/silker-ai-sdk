# Silker AI Detection Benchmark Results

- **Suite:** `core`
- **Package:** `@silker-ai/agent`
- **Version:** `1.5.1`
- **Date:** 2026-06-22
- **Samples:** 210
- **Generated:** 2026-06-22T20:14:33.123Z

## Summary

| Dataset | Policy | N | TPR | Macro TPR | FPR | Precision | TP | FN | FP | TN |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Prompt Injection | llm-route (medium+ or override signal) | 130 | 100.0% | 100.0% | 0.0% | 100.0% | 75 | 0 | 0 | 55 |
| Prompt Injection | non-llm-route (high/critical) | 130 | 100.0% | 100.0% | 0.0% | 100.0% | 75 | 0 | 0 | 55 |
| SQL Injection | block on detection | 40 | 100.0% | 100.0% | 0.0% | 100.0% | 20 | 0 | 0 | 20 |
| XSS | block on detection | 40 | 100.0% | 100.0% | 0.0% | 100.0% | 20 | 0 | 0 | 20 |

## Misclassified samples

### Prompt Injection - llm-route (medium+ or override signal)

_No misclassifications._

### Prompt Injection - non-llm-route (high/critical)

_No misclassifications._

### SQL Injection - block on detection

_No misclassifications._

### XSS - block on detection

_No misclassifications._
