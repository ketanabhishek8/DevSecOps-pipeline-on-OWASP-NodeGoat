# Findings log

One row per finding (or group of findings with the same root cause) from the pipeline. Fill it in during triage and update it as fixes land.
Copy scanner, rule, severity and location from the combined report (Actions run summary or `security-report.json`).

**Verdict:** `True positive`, `False positive` or `Accepted risk` (the last two also go in `.security/accepted-risks.json` with a reason).
**Status:** `Open`, `In progress` or `Fixed`.

## Result

| | Baseline (run #1) | After fixes |
| --- | --- | --- |
| Gate | ❌ Failed | ✅ Passed |
| Blocking (Critical + High) | 70 (11 critical, 59 high) | 0 |
| Open findings, all severities | 154 | 50 (medium/low only) |
| Accepted risks | 0 | 2 (false positives) |

## Blocking findings

| # | Scanner | Rule | Severity | OWASP | Location | Verdict | Fix (commit) | Owner | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Semgrep | `code-string-concat`, njsscan `eval_nodejs` (6 hits) | High | A03 Injection (CWE-95) | `app/routes/contributions.js:32-34` | True positive: user input passed to `eval()` | `065d530` strict whole-number parsing | | Fixed |
| 2 | Semgrep, then ZAP | njsscan `express_open_redirect`; ZAP 10028 Off-site Redirect | High | A01 Broken Access Control (CWE-601) | `app/routes/index.js:72` | True positive: `/learn` redirected to any URL | `64753ab` host allowlist; ZAP still flagged the URL parameter, so `da0fc7c` server-side lookup; Semgrep still saw request data in `redirect()`, so `4afef6b` one fixed route per resource | | Fixed |
| 3 | Semgrep | njsscan `node_ssrf` | High | A10 SSRF (CWE-918) | `app/routes/research.js:15` | True positive: server fetched a client-supplied URL | `fd21c0e` fixed base URL + symbol validation | | Fixed |
| 4 | Semgrep | njsscan `node_password` (2 hits) | High | A07 (CWE-798) | `app/routes/session.js:61, 172` | False positive: error-message strings | `0404280` accepted with reason, review 2027-04-01 | | Accepted |
| 5 | gitleaks | `private-key` | High | A07 (CWE-798) | `app/artifacts/cert/server.key` | True positive: unused key committed | `371617a` key pair deleted, HTTPS reads paths from env | | Fixed |
| 6 | gitleaks | `generic-api-key` (2 hits) | High | A07 (CWE-798) | `app/config/env/development.js:6`, `test.js:6` | True positive: hardcoded ZAP API key | `371617a` read from `ZAP_API_KEY` env var | | Fixed |
| 7 | Trivy | 41 CVEs in `tar`, `set-value`, `minimist`, `nconf`, `braces`, `minimatch`, `fsevents`, … | Critical/High | A06 Vulnerable Components | `package-lock.json` (via `forever`) | True positive: unused dependency | `4f03a86` removed `forever` | | Fixed |
| 8 | Trivy | CVEs in `path-to-regexp`, `qs`, `body-parser`, `underscore` | Critical/High | A06 | `package-lock.json` | True positive | `e605926` upgraded express 4.22.3, body-parser 1.20.8, underscore 1.13.8 | | Fixed |
| 9 | Trivy | `marked@0.3.5` XSS/ReDoS CVEs | High | A06 | `package-lock.json` | True positive | `28f28ee` marked 4.3.0 | | Fixed |
| 10 | Trivy | `bson@1.0.9` (critical), `mongodb@2.2.36` | Critical/High | A06 | `package-lock.json` | True positive | `57d483d` mongodb driver 3.7.4 | | Fixed |
| 11 | Trivy | `swig@1.4.2` CVE-2023-25345 (no fix exists), `minimist@0.0.10` | High/Critical | A06 + A03 XSS (autoescape off) | `package-lock.json`, `server.js` | True positive: abandoned package | `84619de` replaced with Nunjucks, autoescape on | | Fixed |
| 12 | Trivy | `debug@2.2.0` via `helmet@2` | High | A06 | `package-lock.json` | True positive | `276038f` helmet 8, now enabled | | Fixed |

## Also fixed (not flagged by the gate)

| Issue | OWASP | Fix (commit) |
| --- | --- | --- |
| Stored XSS: templates rendered user data unescaped | A03 (CWE-79) | `84619de` Nunjucks autoescape |
| Missing security headers reported by ZAP (CSP, X-Frame-Options, X-Content-Type-Options) and `X-Powered-By` leak | A05 | `276038f` helmet 8 |
| Container ran Node 12 (end of life since April 2022) | A06 | `38870b9` Node 22 LTS, `npm ci` |
| Template break during the swig → Nunjucks migration (all logged-in pages returned 500) | — | `d54a62c`, caught by the CI smoke tests |
| A first open-redirect fix that two different scanners still flagged (shows why SAST and DAST are both needed) | A01 | `da0fc7c`, `4afef6b` |

## Remaining open findings (medium / low, below the gate threshold)

| # | Scanner | Rule | Severity | OWASP | Location | Verdict | Fix (commit) | Owner | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 13 | | | | | | | | | Open |
