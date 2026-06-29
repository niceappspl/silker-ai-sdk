# Silker AI Detection Benchmark Results

- **Suite:** `extended`
- **Package:** `@silker-ai/agent`
- **Version:** `1.6.7`
- **Date:** 2026-06-29
- **Samples:** 1012
- **Generated:** 2026-06-29T19:22:47.853Z

## Summary

| Dataset | Policy | N | TPR | Macro TPR | FPR | Precision | TP | FN | FP | TN |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Prompt Injection | llm-route (medium+ or override signal) | 411 | 100.0% | 100.0% | 0.0% | 100.0% | 294 | 0 | 0 | 117 |
| Prompt Injection | non-llm-route (high/critical) | 411 | 100.0% | 100.0% | 0.0% | 100.0% | 294 | 0 | 0 | 117 |
| SQL Injection | block on detection | 264 | 100.0% | 100.0% | 0.0% | 100.0% | 129 | 0 | 0 | 135 |
| XSS | block on detection | 337 | 100.0% | 100.0% | 0.0% | 100.0% | 191 | 0 | 0 | 146 |

## Misclassified samples

### Prompt Injection - llm-route (medium+ or override signal)

_No misclassifications._

### Prompt Injection - non-llm-route (high/critical)

_No misclassifications._

### SQL Injection - block on detection

_No misclassifications._

### XSS - block on detection

_No misclassifications._
