# Silker AI Detection Benchmark Results

- **Suite:** `community`
- **Package:** `@silker-ai/agent`
- **Version:** `1.6.9`
- **Date:** 2026-09-17
- **Samples:** 1494
- **Generated:** 2026-09-17T19:04:55.574Z

## Summary

| Dataset | Policy | N | TPR | Macro TPR | FPR | Precision | TP | FN | FP | TN |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SQL Injection | block on detection | 986 | 98.2% | 96.7% | 0.0% | 100.0% | 772 | 14 | 0 | 200 |
| XSS | block on detection | 508 | 99.7% | 99.4% | 0.0% | 100.0% | 307 | 1 | 0 | 200 |

## Misclassified samples

### SQL Injection - block on detection

| Type | Category | Sample |
| --- | --- | --- |
| FN | pat-Auth_Bypass | `'-'` |
| FN | pat-Auth_Bypass | `' '` |
| FN | pat-Auth_Bypass | `'&'` |
| FN | pat-Auth_Bypass | `'^'` |
| FN | pat-Auth_Bypass | `'*'` |
| FN | pat-Auth_Bypass | `"-"` |
| FN | pat-Auth_Bypass | `" "` |
| FN | pat-Auth_Bypass | `"&"` |
| FN | pat-Auth_Bypass | `"^"` |
| FN | pat-Auth_Bypass | `"*"` |
| FN | pat-Auth_Bypass2 | `==` |
| FN | pat-Auth_Bypass2 | `=` |
| FN | pat-Auth_Bypass2 | `'` |
| FN | pat-Generic_TimeBased | `'\"` |

### XSS - block on detection

| Type | Category | Sample |
| --- | --- | --- |
| FN | pat-xss_payloads_quick | `<h1>INJECTX</h1>` |
