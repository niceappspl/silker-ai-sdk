# Benchmark categories - what we test

Each sample is `{ text, label, category, source? }`. Detectors and policies are unchanged from production.

## Prompt injection (`detectPromptInjection`)

| Category | Label | What it probes |
| --- | --- | --- |
| `instruction_override` | attack | Ignore/disregard/forget/skip prior instructions |
| `jailbreak` | attack | DAN, developer mode, unrestricted roleplay |
| `system_prompt_extraction` | attack | Repeat/show/reveal system prompt |
| `data_exfiltration_via_llm` | attack | Encode/translate/spell-out system prompt |
| `delimiter_injection` | attack | `<\|system\|>`, `[INST]`, markdown system blocks |
| `role_manipulation` | attack | Malicious persona (grandma exploit, hacker roleplay) |
| `multilingual_*` | attack | Instruction override in non-English scripts |
| `token_smuggling` | attack | Zero-width / invisible chars between words |
| `encoding_obfuscation` | attack | base64, hex, unicode escapes hiding instructions |
| `adversarial_leetspeak` | attack | Character substitutions (1gn0r3…) |
| `adversarial_letter_spacing` | attack | Spaced letters (i g n o r e…) |
| `chain_manipulation` | attack | Multi-step override chains |
| `obfuscated_keywords` | attack | D.A.N, D-A-N spacing tricks |
| `legit_roleplay_ux` | benign | Act as translator, pretend pirate, etc. |
| `benign_stress` | benign | "ignore typos", benign base64, SQL keywords in prose |
| `normal_question` | benign | Regular user questions |

**Policies:** LLM-route (`shouldBlockPromptInjectionOnLlmRoute`) vs non-LLM (high/critical only).

## SQL injection (`detectSqliHeuristic`)

| Category | Label | What it probes |
| --- | --- | --- |
| `tautology` | attack | `' OR 1=1`, `' OR 'a'='a` |
| `union_based` | attack | UNION SELECT exfiltration |
| `time_based` | attack | SLEEP, WAITFOR DELAY, pg_sleep |
| `boolean_based` | attack | Conditional true/false inference |
| `piggybacked` | attack | Stacked queries DROP/INSERT/EXEC |
| `comment_injection` | attack | `--`, `#` comment termination |
| `blind` / `error_based` | attack | Substring/EXTRACTVALUE/updatexml |
| `benign_keyword_*` | benign | SELECT/drop/union in normal English |

## XSS (`detectXssHeuristic`)

| Category | Label | What it probes |
| --- | --- | --- |
| `script_tag` | attack | `<script>`, srcdoc, nested SVG script |
| `event_handler` | attack | onerror, onload, onfocus, ontoggle… |
| `js_protocol` | attack | javascript: URLs |
| `data_uri` | attack | data:text/html base64 payloads |
| `encoded_js_protocol` | attack | HTML/unicode encoded javascript: |
| `dom_mutation` | attack | prototype pollution style script sinks |
| `benign_*` | benign | HTML docs, JS terms in prose, security best practices |
