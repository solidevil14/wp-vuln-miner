# wp-vuln-miner

Static-analysis pipeline for hunting unpublished vulnerabilities in
wordpress.org plugins, with responsible disclosure as the end goal
(report → patch → CVE via CNA).

```
fetch_plugins.py          # catalog + download (sweet-spot filters)
scan.py                   # taint-pattern audit: hook context -> source -> sink
plugins/                  # extracted plugin code (gitignored)
findings/                 # findings.json + REPORT.md triage output
docs/CVE_PATH.md          # how CVEs actually get assigned (Patchstack/WF CNA)
docs/report_template.md   # disclosure report skeleton
poc_templates/            # curl PoC recipes per vuln class (local lab only)
```

## Workflow

```bash
# 1. pull fresh, low-install, actively-maintained plugins
python3 fetch_plugins.py --browse new --pages 3 --max-installs 3000 --download 20

# 2. static audit
python3 scan.py --plugins-dir plugins --out findings
less findings/REPORT.md        # sorted by severity, hook context attached

# 3. manually verify the >= 7.0 items against your local docker WP instance
#    (see poc_templates/), starting from nopriv hooks and REST routes with
#    permission_callback missing or __return_true

# 4. confirm one → docs/report_template.md → Patchstack (docs/CVE_PATH.md)
```

## What the scanner looks for

| Class | Sinks |
|---|---|
| RCE | `eval`, `system`, `exec`, `shell_exec`, `passthru`, `proc_open`, ... |
| SQLi | `$wpdb->query/get_*` without `prepare` |
| Deserialization | `unserialize` / `maybe_unserialize` on request data |
| File ops | read/write/delete/include with tainted paths |
| SSRF | `wp_remote_*`, `curl_exec` on tainted URLs |
| Redirect | `wp_redirect` on tainted input |
| XSS | echo/print of tainted values |

Hook-context awareness: `wp_ajax_nopriv_*` and `admin_post_nopriv_*` map to
**unauthenticated**, `wp_ajax_*` to logged-in, REST routes are checked for a
real `permission_callback`. Severity adjusts for auth level, nonce guards,
and sanitizer presence on the sink line.

The scanner is a triage filter, not a verdict: every ≥7.0 finding needs eyes
and a working local PoC before anything is reported.

## Scope & ethics

wordpress.org plugin code is GPL and public — static auditing is legal and
expected. PoCs run exclusively against a local WordPress instance you own.
Disclosure is coordinated, through CNAs (Patchstack / Wordfence). No probing
of live third-party sites, ever.
