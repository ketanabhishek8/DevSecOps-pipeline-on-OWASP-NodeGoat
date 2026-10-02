## Security pipeline report

**Gate: ❌ FAILED** — 70 finding(s) at or above **high** severity.

Policy: fail on `high` and above · 154 open finding(s) · 0 accepted risk(s)

### Findings by scanner

| Scanner | Layer | Critical | High | Medium | Low | Info |
| --- | --- | --- | --- | --- | --- | --- |
| semgrep | SAST · source code | 0 | 10 | 28 | 4 | 0 |
| trivy | SCA · dependencies | 11 | 46 | 22 | 11 | 0 |
| gitleaks | Secrets · hardcoded credentials | 0 | 3 | 0 | 0 | 0 |
| zap | DAST · running app | 0 | 0 | 5 | 7 | 7 |
| **Total** | | **11** | **59** | **55** | **22** | **7** |

### Findings by OWASP Top 10 (2021)

| Category | Findings |
| --- | --- |
| A01 Broken Access Control | 4 |
| A02 Cryptographic Failures | 5 |
| A03 Injection | 4 |
| A04 Insecure Design | 7 |
| A05 Security Misconfiguration | 5 |
| A06 Vulnerable and Outdated Components | 90 |
| A07 Identification and Authentication Failures | 3 |
| A08 Software and Data Integrity Failures | 1 |
| Not mapped | 35 |

### Blocking findings

| Severity | Scanner | OWASP | Finding | Location |
| --- | --- | --- | --- | --- |
| CRITICAL | trivy | A06 | [minimist@1.2.5: minimist: prototype pollution](https://avd.aquasec.com/nvd/cve-2021-44906) — Fixed in 1.2.6, 0.2.4 | `package-lock.json:12596` |
| CRITICAL | trivy | A06 | [set-value@2.0.0: nodejs-set-value: prototype pollution in function set-value](https://avd.aquasec.com/nvd/cve-2019-10747) — Fixed in 2.0.1, 3.0.1 | `package-lock.json:13352` |
| CRITICAL | trivy | A06 | [underscore@1.9.1: nodejs-underscore: Arbitrary code execution via the template function](https://avd.aquasec.com/nvd/cve-2021-23358) — Fixed in 1.12.1 | `package-lock.json:14445` |
| CRITICAL | trivy | A06 | [set-value@0.4.3: nodejs-set-value: prototype pollution in function set-value](https://avd.aquasec.com/nvd/cve-2019-10747) — Fixed in 2.0.1, 3.0.1 | `package-lock.json:14498` |
| CRITICAL | trivy | A06 | [minimist@1.2.0: minimist: prototype pollution](https://avd.aquasec.com/nvd/cve-2021-44906) — Fixed in 1.2.6, 0.2.4 | `package-lock.json:1524` |
| CRITICAL | trivy | A06 | [fsevents@1.2.9: Code injection in fsevents](https://avd.aquasec.com/nvd/cve-2023-45311) — Fixed in 1.2.11 | `package-lock.json:3286` |
| CRITICAL | trivy | A06 | [minimist@0.0.8: minimist: prototype pollution](https://avd.aquasec.com/nvd/cve-2021-44906) — Fixed in 1.2.6, 0.2.4 | `package-lock.json:3553` |
| CRITICAL | trivy | A06 | [tar@4.4.8: tar: node-tar: Denial of Service via crafted gzip bomb](https://avd.aquasec.com/nvd/cve-2026-59873) — Fixed in 7.5.19 | `package-lock.json:3876` |
| CRITICAL | trivy | A06 | [minimist@0.0.10: minimist: prototype pollution](https://avd.aquasec.com/nvd/cve-2021-44906) — Fixed in 1.2.6, 0.2.4 | `package-lock.json:6876` |
| CRITICAL | trivy | A06 | [mixin-deep@1.3.1: nodejs-mixin-deep: prototype pollution in function mixin-deep](https://avd.aquasec.com/nvd/cve-2019-10746) — Fixed in 1.3.2, 2.0.1 | `package-lock.json:6881` |
| CRITICAL | trivy | A06 | [bson@1.0.9: bson: Deserialization of Untrusted Data could result in Code injection or Excessive CPU load](https://avd.aquasec.com/nvd/cve-2020-7610) — Fixed in 1.1.4 | `package-lock.json:897` |
| HIGH | gitleaks | A07 | Identified a Private Key, which may compromise cryptographic security and sensitive data encryption. | `app/artifacts/cert/server.key:1` |
| HIGH | gitleaks | A07 | Detected a Generic API Key, potentially exposing access to various services and sensitive operations. | `app/config/env/development.js:6` |
| HIGH | gitleaks | A07 | Detected a Generic API Key, potentially exposing access to various services and sensitive operations. | `app/config/env/test.js:6` |
| HIGH | semgrep | A03 | [Found data from an Express or Next web request flowing to `eval`. If this data is user-controllable this can lead to execution of arbitrary…](https://semgrep.dev/r/javascript.lang.security.audit.code-string-concat.code-string-concat) | `app/app/routes/contributions.js:32` |
| HIGH | semgrep | A03 | [Found data from an Express or Next web request flowing to `eval`. If this data is user-controllable this can lead to execution of arbitrary…](https://semgrep.dev/r/javascript.lang.security.audit.code-string-concat.code-string-concat) | `app/app/routes/contributions.js:33` |
| HIGH | semgrep | A03 | [Found data from an Express or Next web request flowing to `eval`. If this data is user-controllable this can lead to execution of arbitrary…](https://semgrep.dev/r/javascript.lang.security.audit.code-string-concat.code-string-concat) | `app/app/routes/contributions.js:34` |
| HIGH | semgrep | — | [User controlled data in eval() or similar functions may result in Server Side Injection or Remote Code Injection](https://semgrep.dev/r/ajinabraham.njsscan.eval.eval_node.eval_nodejs) | `app/app/routes/contributions.js:32` |
| HIGH | semgrep | — | [User controlled data in eval() or similar functions may result in Server Side Injection or Remote Code Injection](https://semgrep.dev/r/ajinabraham.njsscan.eval.eval_node.eval_nodejs) | `app/app/routes/contributions.js:33` |
| HIGH | semgrep | — | [User controlled data in eval() or similar functions may result in Server Side Injection or Remote Code Injection](https://semgrep.dev/r/ajinabraham.njsscan.eval.eval_node.eval_nodejs) | `app/app/routes/contributions.js:34` |
| HIGH | semgrep | — | [Untrusted user input in redirect() can result in Open Redirect vulnerability. An http parameter may contain a URL value and could cause the…](https://semgrep.dev/r/ajinabraham.njsscan.redirect.open_redirect.express_open_redirect) | `app/app/routes/index.js:72` |
| HIGH | semgrep | — | [User controlled URL in http client libraries can result in Server Side Request Forgery (SSRF).](https://semgrep.dev/r/ajinabraham.njsscan.ssrf.ssrf_node.node_ssrf) | `app/app/routes/research.js:15` |
| HIGH | semgrep | — | [A hardcoded password in plain text is identified. Store it properly in an environment variable.](https://semgrep.dev/r/ajinabraham.njsscan.generic.hardcoded_secrets.node_password) | `app/app/routes/session.js:172` |
| HIGH | semgrep | — | [A hardcoded password in plain text is identified. Store it properly in an environment variable.](https://semgrep.dev/r/ajinabraham.njsscan.generic.hardcoded_secrets.node_password) | `app/app/routes/session.js:61` |
| HIGH | trivy | A06 | [y18n@3.2.1: nodejs-y18n: prototype pollution vulnerability](https://avd.aquasec.com/nvd/cve-2020-7774) — Fixed in 3.2.2, 4.0.1, 5.0.5 | `package-lock.json:11898` |
| HIGH | trivy | A06 | [path-to-regexp@0.1.7: path-to-regexp: Backtracking regular expressions cause ReDoS](https://avd.aquasec.com/nvd/cve-2024-45296) — Fixed in 1.9.0, 0.1.10, 8.0.0, 3.3.0, 6.3.0 | `package-lock.json:12485` |
| HIGH | trivy | A06 | [path-to-regexp@0.1.7: path-to-regexp: path-to-regexp Unpatched `path-to-regexp` ReDoS in 0.1.x](https://avd.aquasec.com/nvd/cve-2024-52798) — Fixed in 0.1.12 | `package-lock.json:12485` |
| HIGH | trivy | A06 | [path-to-regexp@0.1.7: path-to-regexp: path-to-regexp: Denial of Service via catastrophic backtracking from malformed URL …](https://avd.aquasec.com/nvd/cve-2026-4867) — Fixed in 0.1.13 | `package-lock.json:12485` |
| HIGH | trivy | A06 | [qs@6.5.2: express: "qs" prototype poisoning causes the hang of the node process](https://avd.aquasec.com/nvd/cve-2022-24999) — Fixed in 6.10.3, 6.9.7, 6.8.3, 6.7.3, 6.6.1, 6.5.3, 6.4.1, 6.3.3, 6.2.4 | `package-lock.json:12723` |
| HIGH | trivy | A06 | [semver@5.6.0: nodejs-semver: Regular expression denial of service](https://avd.aquasec.com/nvd/cve-2022-25883) — Fixed in 7.5.2, 6.3.1, 5.7.2 | `package-lock.json:13262` |
| HIGH | trivy | A06 | [set-value@2.0.0: nodejs-set-value: type confusion allows bypass of CVE-2019-10747](https://avd.aquasec.com/nvd/cve-2021-23440) — Fixed in 4.0.1, 2.0.1, 3.0.3 | `package-lock.json:13352` |
| HIGH | trivy | A06 | [debug@2.2.0: A vulnerability classified as problematic has been found in debug-js d ...](https://avd.aquasec.com/nvd/cve-2017-20165) — Fixed in 3.1.0, 2.6.9 | `package-lock.json:1384` |
| HIGH | trivy | A06 | [swig@1.4.2: Arbitrary local file read vulnerability during template rendering](https://avd.aquasec.com/nvd/cve-2023-25345) — Fixed in Link: [CVE-2023-25345](https://avd.aquasec.com/nvd/cve-2023-25345) | `package-lock.json:14000` |
| HIGH | trivy | A06 | [underscore@1.9.1: Underscore.js: Underscore.js: Denial of Service via recursive data structures in flatten and isEqua…](https://avd.aquasec.com/nvd/cve-2026-27601) — Fixed in 1.13.8 | `package-lock.json:14445` |
| HIGH | trivy | A06 | [set-value@0.4.3: nodejs-set-value: type confusion allows bypass of CVE-2019-10747](https://avd.aquasec.com/nvd/cve-2021-23440) — Fixed in 4.0.1, 2.0.1, 3.0.3 | `package-lock.json:14498` |
| HIGH | trivy | A06 | [decode-uri-component@0.2.0: decode-uri-component: improper input validation resulting in DoS](https://avd.aquasec.com/nvd/cve-2022-38900) — Fixed in 0.2.1 | `package-lock.json:2072` |
| HIGH | trivy | A06 | [ini@1.3.5: nodejs-ini: Prototype pollution via malicious INI file](https://avd.aquasec.com/nvd/cve-2020-7788) — Fixed in 1.3.6 | `package-lock.json:3514` |
| HIGH | trivy | A06 | [minimatch@3.0.4: nodejs-minimatch: ReDoS via the braceExpand function](https://avd.aquasec.com/nvd/cve-2022-3517) — Fixed in 3.0.5 | `package-lock.json:3541` |
| HIGH | trivy | A06 | [minimatch@3.0.4: minimatch: minimatch: Denial of Service via specially crafted glob patterns](https://avd.aquasec.com/nvd/cve-2026-26996) — Fixed in 10.2.1, 9.0.6, 8.0.5, 7.4.7, 6.2.1, 5.1.7, 4.2.4, 3.1.3 | `package-lock.json:3541` |
| HIGH | trivy | A06 | [minimatch@3.0.4: minimatch: minimatch: Denial of Service due to unbounded recursive backtracking via crafted glob pa…](https://avd.aquasec.com/nvd/cve-2026-27903) — Fixed in 10.2.3, 9.0.7, 8.0.6, 7.4.8, 6.2.2, 5.1.8, 4.2.5, 3.1.3 | `package-lock.json:3541` |
| HIGH | trivy | A06 | [minimatch@3.0.4: minimatch: Minimatch: Denial of Service via catastrophic backtracking in glob expressions](https://avd.aquasec.com/nvd/cve-2026-27904) — Fixed in 10.2.3, 9.0.7, 8.0.6, 7.4.8, 6.2.2, 5.1.8, 4.2.5, 3.1.4 | `package-lock.json:3541` |
| HIGH | trivy | A06 | [semver@5.7.0: nodejs-semver: Regular expression denial of service](https://avd.aquasec.com/nvd/cve-2022-25883) — Fixed in 7.5.2, 6.3.1, 5.7.2 | `package-lock.json:3811` |
| HIGH | trivy | A06 | [tar@4.4.8: nodejs-tar: Insufficient symlink protection allowing arbitrary file creation and overwrite](https://avd.aquasec.com/nvd/cve-2021-32803) — Fixed in 3.2.3, 4.4.15, 5.0.7, 6.1.2 | `package-lock.json:3876` |
| HIGH | trivy | A06 | [tar@4.4.8: nodejs-tar: Insufficient absolute path sanitization allowing arbitrary file creation and overwrite](https://avd.aquasec.com/nvd/cve-2021-32804) — Fixed in 3.2.2, 4.4.14, 5.0.6, 6.1.1 | `package-lock.json:3876` |
| HIGH | trivy | A06 | [tar@4.4.8: nodejs-tar: Insufficient symlink protection due to directory cache poisoning using symbolic links a…](https://avd.aquasec.com/nvd/cve-2021-37701) — Fixed in 4.4.16, 5.0.8, 6.1.7 | `package-lock.json:3876` |
| HIGH | trivy | A06 | [tar@4.4.8: nodejs-tar: Insufficient symlink protection due to directory cache poisoning using symbolic links a…](https://avd.aquasec.com/nvd/cve-2021-37712) — Fixed in 4.4.18, 5.0.10, 6.1.9 | `package-lock.json:3876` |
| HIGH | trivy | A06 | [tar@4.4.8: nodejs-tar: Arbitrary File Creation/Overwrite on Windows via insufficient relative path sanitization](https://avd.aquasec.com/nvd/cve-2021-37713) — Fixed in 4.4.18, 5.0.10, 6.1.9 | `package-lock.json:3876` |
| HIGH | trivy | A06 | [tar@4.4.8: node-tar: tar: node-tar: Arbitrary file overwrite and symlink poisoning via unsanitized linkpaths i…](https://avd.aquasec.com/nvd/cve-2026-23745) — Fixed in 7.5.3 | `package-lock.json:3876` |
| HIGH | trivy | A06 | [tar@4.4.8: node-tar: tar: node-tar: Arbitrary file overwrite via Unicode path collision race condition](https://avd.aquasec.com/nvd/cve-2026-23950) — Fixed in 7.5.4 | `package-lock.json:3876` |
| HIGH | trivy | A06 | [tar@4.4.8: node-tar: tar: node-tar: Arbitrary file creation via path traversal bypass in hardlink security che…](https://avd.aquasec.com/nvd/cve-2026-24842) — Fixed in 7.5.7 | `package-lock.json:3876` |
| HIGH | trivy | A06 | [tar@4.4.8: node-tar: node-tar: Arbitrary file read/write via malicious archive hardlink creation](https://avd.aquasec.com/nvd/cve-2026-26960) — Fixed in 7.5.8 | `package-lock.json:3876` |
| HIGH | trivy | A06 | [tar@4.4.8: node-tar: hardlink path traversal via drive-relative linkpath](https://avd.aquasec.com/nvd/cve-2026-29786) — Fixed in 7.5.10 | `package-lock.json:3876` |
| HIGH | trivy | A06 | [tar@4.4.8: tar: tar: File overwrite via drive-relative symlink traversal](https://avd.aquasec.com/nvd/cve-2026-31802) — Fixed in 7.5.11 | `package-lock.json:3876` |
| HIGH | trivy | A06 | [tar@4.4.8: tar: Node-tar: Denial of Service via malformed tar archive header](https://avd.aquasec.com/nvd/cve-2026-59874) — Fixed in 7.5.18 | `package-lock.json:3876` |
| HIGH | trivy | A06 | [tar@4.4.8: tar: node-tar: Denial of Service via crafted long-path tar archive](https://avd.aquasec.com/nvd/cve-2026-73566) — Fixed in 7.5.21 | `package-lock.json:3876` |
| HIGH | trivy | A06 | [i@0.3.6: inflect vulnerable to Inefficient Regular Expression Complexity](https://avd.aquasec.com/nvd/cve-2021-3820) — Fixed in 0.3.7 | `package-lock.json:5124` |
| HIGH | trivy | A06 | [kind-of@6.0.2: nodejs-kind-of: ctorName in index.js allows external user input to overwrite certain internal attri…](https://avd.aquasec.com/nvd/cve-2019-20149) — Fixed in 6.0.3 | `package-lock.json:554` |
| HIGH | trivy | A06 | [body-parser@1.18.3: body-parser: Denial of Service Vulnerability in body-parser](https://avd.aquasec.com/nvd/cve-2024-45590) — Fixed in 1.20.3 | `package-lock.json:637` |
| HIGH | trivy | A06 | [marked@0.3.5: The marked module is vulnerable to a regular expression denial of serv ...](https://avd.aquasec.com/nvd/cve-2017-16114) — Fixed in 0.3.9 | `package-lock.json:6742` |
| HIGH | trivy | A06 | [marked@0.3.5: marked: regular expression block.def may lead Denial of Service](https://avd.aquasec.com/nvd/cve-2022-21680) — Fixed in 4.0.10 | `package-lock.json:6742` |

_…and 10 more in `security-report.json`._

<details>
<summary>Other findings (84, below the gate threshold)</summary>

| Severity | Scanner | OWASP | Finding | Location |
| --- | --- | --- | --- | --- |
| MEDIUM | semgrep | A01 | [The application redirects to a URL specified by user-supplied input `req` that is not validated. This could redirect users to malicious loc…](https://semgrep.dev/r/javascript.express.security.audit.express-open-redirect.express-open-redirect) | `app/app/routes/index.js:72` |
| MEDIUM | semgrep | A02 | [This link points to a plaintext HTTP URL. Prefer an encrypted HTTPS URL if possible.](https://semgrep.dev/r/html.security.plaintext-http-link.plaintext-http-link) | `app/app/views/tutorial/a2.html:207` |
| MEDIUM | semgrep | A02 | [This link points to a plaintext HTTP URL. Prefer an encrypted HTTPS URL if possible.](https://semgrep.dev/r/html.security.plaintext-http-link.plaintext-http-link) | `app/app/views/tutorial/a2.html:209` |
| MEDIUM | semgrep | A02 | [This link points to a plaintext HTTP URL. Prefer an encrypted HTTPS URL if possible.](https://semgrep.dev/r/html.security.plaintext-http-link.plaintext-http-link) | `app/app/views/tutorial/a2.html:210` |
| MEDIUM | semgrep | A02 | [This link points to a plaintext HTTP URL. Prefer an encrypted HTTPS URL if possible.](https://semgrep.dev/r/html.security.plaintext-http-link.plaintext-http-link) | `app/app/views/tutorial/a5.html:50` |
| MEDIUM | semgrep | A02 | [This link points to a plaintext HTTP URL. Prefer an encrypted HTTPS URL if possible.](https://semgrep.dev/r/html.security.plaintext-http-link.plaintext-http-link) | `app/app/views/tutorial/a5.html:51` |
| MEDIUM | semgrep | A04 | [Don’t use the default session cookie name Using the default session cookie name can open your app to attacks. The security issue posed is s…](https://semgrep.dev/r/javascript.express.security.audit.express-cookie-settings.express-cookie-session-default-name) | `app/server.js:78` |
| MEDIUM | semgrep | A04 | [Default session middleware settings: `domain` not set. It indicates the domain of the cookie; use it to compare against the domain of the s…](https://semgrep.dev/r/javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-domain) | `app/server.js:78` |
| MEDIUM | semgrep | A04 | [Default session middleware settings: `expires` not set. Use it to set expiration date for persistent cookies.](https://semgrep.dev/r/javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-expires) | `app/server.js:78` |
| MEDIUM | semgrep | A04 | [Default session middleware settings: `httpOnly` not set. It ensures the cookie is sent only over HTTP(S), not client JavaScript, helping to…](https://semgrep.dev/r/javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-httponly) | `app/server.js:78` |
| MEDIUM | semgrep | A04 | [Default session middleware settings: `path` not set. It indicates the path of the cookie; use it to compare against the request path. If th…](https://semgrep.dev/r/javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-path) | `app/server.js:78` |
| MEDIUM | semgrep | A04 | [Default session middleware settings: `secure` not set. It ensures the browser only sends the cookie over HTTPS.](https://semgrep.dev/r/javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-secure) | `app/server.js:78` |
| MEDIUM | semgrep | — | [crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.](https://semgrep.dev/r/ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator) | `app/app/data/user-dao.js:51` |
| MEDIUM | semgrep | — | [crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.](https://semgrep.dev/r/ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator) | `app/app/data/user-dao.js:52` |
| MEDIUM | semgrep | — | [crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.](https://semgrep.dev/r/ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator) | `app/app/data/user-dao.js:53` |
| MEDIUM | semgrep | — | [Ensure that the regex used to compare with user supplied input is safe from regular expression denial of service.](https://semgrep.dev/r/ajinabraham.njsscan.dos.regex_dos.regex_dos) | `app/app/routes/session.js:159` |
| MEDIUM | semgrep | — | [crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.](https://semgrep.dev/r/ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator) | `app/app/routes/session.js:16` |
| MEDIUM | semgrep | — | [A hardcoded username in plain text is identified. Store it properly in an environment variable.](https://semgrep.dev/r/ajinabraham.njsscan.generic.hardcoded_secrets.node_username) | `app/app/routes/session.js:160` |
| MEDIUM | semgrep | — | [crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.](https://semgrep.dev/r/ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator) | `app/app/routes/session.js:17` |
| MEDIUM | semgrep | — | [String comparisons using '===', '!==', '!=' and '==' is vulnerable to timing attacks. A timing attack allows the attacker to learn potentia…](https://semgrep.dev/r/ajinabraham.njsscan.crypto.timing_attack_node.node_timing_attack) | `app/app/routes/session.js:176` |
| MEDIUM | semgrep | — | [A hardcoded username in plain text is identified. Store it properly in an environment variable.](https://semgrep.dev/r/ajinabraham.njsscan.generic.hardcoded_secrets.node_username) | `app/app/routes/session.js:213` |
| MEDIUM | semgrep | — | [A hardcoded username in plain text is identified. Store it properly in an environment variable.](https://semgrep.dev/r/ajinabraham.njsscan.generic.hardcoded_secrets.node_username) | `app/app/routes/session.js:60` |
| MEDIUM | semgrep | — | [Untrusted user input in express render() function can result in arbitrary file read if hbs templating is used.](https://semgrep.dev/r/ajinabraham.njsscan.traversal.express_hbs_lfr.express_lfr_warning) | `app/app/routes/tutorial.js:10` |
| MEDIUM | semgrep | — | [Untrusted user input in express render() function can result in arbitrary file read if hbs templating is used.](https://semgrep.dev/r/ajinabraham.njsscan.traversal.express_hbs_lfr.express_lfr_warning) | `app/app/routes/tutorial.js:33` |
| MEDIUM | semgrep | — | [crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.](https://semgrep.dev/r/ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator) | `app/artifacts/db-reset.js:113` |
| MEDIUM | semgrep | — | [crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.](https://semgrep.dev/r/ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator) | `app/artifacts/db-reset.js:114` |
| MEDIUM | semgrep | — | [Default session middleware settings: `sameSite` attribute is not configured to strict or lax. These configurations provides protection agai…](https://semgrep.dev/r/ajinabraham.njsscan.headers.header_cookie.cookie_session_no_samesite) | `app/server.js:78` |
| MEDIUM | semgrep | — | [Default session middleware settings: `secure` not set. It ensures the browser only sends the cookie over HTTPS.](https://semgrep.dev/r/ajinabraham.njsscan.headers.header_cookie.cookie_session_no_secure) | `app/server.js:78` |
| MEDIUM | trivy | A06 | [qs@6.5.2: qs: qs: Denial of Service via improper input validation in array parsing](https://avd.aquasec.com/nvd/cve-2025-15284) — Fixed in 6.14.1 | `package-lock.json:12723` |
| MEDIUM | trivy | A06 | [qs@6.5.2: qs: qs: Denial of Service via improper validation in stringify function](https://avd.aquasec.com/nvd/cve-2026-82417) — Fixed in 6.16.0 | `package-lock.json:12723` |
| MEDIUM | trivy | A06 | [ms@0.7.1: Vercel ms Inefficient Regular Expression Complexity vulnerability](https://avd.aquasec.com/nvd/cve-2017-20162) — Fixed in 2.0.0 | `package-lock.json:1406` |
| MEDIUM | trivy | A06 | [uglify-js@2.4.24: The uglify-js package before 2.6.0 for Node.js allows attackers to cau ...](https://avd.aquasec.com/nvd/cve-2015-8858) — Fixed in >=2.6.0 | `package-lock.json:14372` |
| MEDIUM | trivy | A06 | [minimist@1.2.0: nodejs-minimist: prototype pollution allows adding or modifying properties of Object.prototype usin…](https://avd.aquasec.com/nvd/cve-2020-7598) — Fixed in 0.2.1, 1.2.3 | `package-lock.json:1524` |
| MEDIUM | trivy | A06 | [decode-uri-component@0.2.0: decode-uri-component: decode-uri-component: Denial of Service via crafted input](https://avd.aquasec.com/nvd/cve-2026-45822) — Fixed in 0.5.0 | `package-lock.json:2072` |
| MEDIUM | trivy | A06 | [express@4.16.4: express: cause malformed URLs to be evaluated](https://avd.aquasec.com/nvd/cve-2024-29041) — Fixed in 4.19.2, 5.0.0-beta.3 | `package-lock.json:2684` |
| MEDIUM | trivy | A06 | [minimist@0.0.8: nodejs-minimist: prototype pollution allows adding or modifying properties of Object.prototype usin…](https://avd.aquasec.com/nvd/cve-2020-7598) — Fixed in 0.2.1, 1.2.3 | `package-lock.json:3553` |
| MEDIUM | trivy | A06 | [tar@4.4.8: node-tar: denial of service while parsing a tar file due to lack of folders depth validation](https://avd.aquasec.com/nvd/cve-2024-28863) — Fixed in 6.2.1 | `package-lock.json:3876` |
| MEDIUM | trivy | A06 | [tar@4.4.8: node-tar: node-tar: File smuggling due to inconsistent tar archive parsing](https://avd.aquasec.com/nvd/cve-2026-53655) — Fixed in 7.5.16 | `package-lock.json:3876` |
| MEDIUM | trivy | A06 | [tar@4.4.8: node-tar: node-tar: Denial of Service due to incorrect PAX path handling](https://avd.aquasec.com/nvd/cve-2026-59871) — Fixed in 7.5.18 | `package-lock.json:3876` |
| MEDIUM | trivy | A06 | [tar@4.4.8: node-tar: node-tar: Denial of Service via crafted archive with NUL bytes in metadata](https://avd.aquasec.com/nvd/cve-2026-59875) — Fixed in 7.5.17 | `package-lock.json:3876` |
| MEDIUM | trivy | A06 | [helmet-csp@1.2.2: Configuration Override in helmet-csp](https://github.com/advisories/GHSA-c3m8-x3cg-qm2c) — Fixed in 2.9.1 | `package-lock.json:4986` |
| MEDIUM | trivy | A06 | [micromatch@3.1.10: micromatch: vulnerable to Regular Expression Denial of Service](https://avd.aquasec.com/nvd/cve-2024-4067) — Fixed in 4.0.8 | `package-lock.json:6332` |
| MEDIUM | trivy | A06 | [marked@0.3.5: marked is an application that is meant to parse and compile markdown.  ...](https://avd.aquasec.com/nvd/cve-2016-10531) — Fixed in 0.3.6 | `package-lock.json:6742` |
| MEDIUM | trivy | A06 | [marked@0.3.5: marked version 0.3.6 and earlier is vulnerable to an XSS attack in the ...](https://avd.aquasec.com/nvd/cve-2017-1000427) — Fixed in 0.3.7 | `package-lock.json:6742` |
| MEDIUM | trivy | A06 | [marked@0.3.5: Marked prior to version 0.3.17 is vulnerable to a Regular Expression D ...](https://avd.aquasec.com/nvd/cve-2018-25110) — Fixed in 0.3.17 | `package-lock.json:6742` |
| MEDIUM | trivy | A06 | marked@0.3.5: Sanitization bypass using HTML Entities — Fixed in >=0.3.6 | `package-lock.json:6742` |
| MEDIUM | trivy | A06 | [minimist@0.0.10: nodejs-minimist: prototype pollution allows adding or modifying properties of Object.prototype usin…](https://avd.aquasec.com/nvd/cve-2020-7598) — Fixed in 0.2.1, 1.2.3 | `package-lock.json:6876` |
| MEDIUM | trivy | A06 | [brace-expansion@1.1.11: brace-expansion: brace-expansion: Denial of Service via crafted brace patterns](https://avd.aquasec.com/nvd/cve-2026-102277) — Fixed in 5.0.12, 3.0.9, 2.1.7, 1.1.21 | `package-lock.json:765` |
| MEDIUM | trivy | A06 | [brace-expansion@1.1.11: brace-expansion: brace-expansion: Denial of Service via zero step value in brace pattern](https://avd.aquasec.com/nvd/cve-2026-33750) — Fixed in 5.0.5, 3.0.2, 2.0.3, 1.1.13 | `package-lock.json:765` |
| MEDIUM | trivy | A06 | [bson@1.0.9: Incorrect parsing of certain JSON input may result in js-bson not corr ...](https://avd.aquasec.com/nvd/cve-2019-2391) — Fixed in 1.1.4 | `package-lock.json:897` |
| MEDIUM | zap | A01 | [Source Code Disclosure - SQL](https://www.zaproxy.org/docs/alerts/10099/) — 2 URL(s) affected | `http://localhost:4000/tutorial` |
| MEDIUM | zap | A04 | [Missing Anti-clickjacking Header](https://www.zaproxy.org/docs/alerts/10020/) — 5 URL(s) affected | `http://localhost:4000` |
| MEDIUM | zap | A05 | [Content Security Policy (CSP) Header Not Set](https://www.zaproxy.org/docs/alerts/10038/) — 5 URL(s) affected | `http://localhost:4000` |
| MEDIUM | zap | A05 | [CSP: Failure to Define Directive with No Fallback](https://www.zaproxy.org/docs/alerts/10055/) — 5 URL(s) affected | `http://localhost:4000/a` |
| MEDIUM | zap | — | [Vulnerable JS Library](https://www.zaproxy.org/docs/alerts/10003/) — 2 URL(s) affected | `http://localhost:4000/vendor/bootstrap/bootstrap.js` |
| LOW | semgrep | — | [Consider changing the default session cookie name. An attacker can use it to fingerprint the server and target attacks accordingly.](https://semgrep.dev/r/ajinabraham.njsscan.headers.header_cookie.cookie_session_default) | `app/server.js:78` |
| LOW | semgrep | — | [Default session middleware settings: `domain` not set. It indicates the domain of the cookie; use it to compare against the domain of the s…](https://semgrep.dev/r/ajinabraham.njsscan.headers.header_cookie.cookie_session_no_domain) | `app/server.js:78` |
| LOW | semgrep | — | [Session middleware settings: `maxAge` not set. Use it to set expiration date for cookies.](https://semgrep.dev/r/ajinabraham.njsscan.headers.header_cookie.cookie_session_no_maxage) | `app/server.js:78` |
| LOW | semgrep | — | [Default session middleware settings: `path` not set. It indicates the path of the cookie; use it to compare against the request path. If th…](https://semgrep.dev/r/ajinabraham.njsscan.headers.header_cookie.cookie_session_no_path) | `app/server.js:78` |
| LOW | trivy | A06 | [on-headers@1.0.1: on-headers: on-headers vulnerable to http response header manipulation](https://avd.aquasec.com/nvd/cve-2025-7339) — Fixed in 1.1.0 | `package-lock.json:12166` |

_…and 24 more in `security-report.json`._

</details>

