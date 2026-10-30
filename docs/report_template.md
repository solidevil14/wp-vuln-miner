# Vulnerability report — <PLUGIN NAME> <= <VERSION>

**Class:** (SQLi / RCE / Deserialization / LFI / SSRF / XSS / CSRF)
**Affected versions:** <= <last affected>
**Patched in:** (leave blank — vendor decides)
**Requires:** (Unauthenticated / Subscriber+ / Contributor+ / Admin without unfiltered_html)
**CVSS 3.1 estimate:** <vector + score, e.g. 9.8 Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H>

## Summary

Two or three sentences: what the flawed code does, who can reach it, what it
yields.

## Root cause

File/line references from the plugin source:

```php
<paste the vulnerable snippet, short>
```

Explain the flow: entry point (hook/route) -> tainted input -> sink -> impact.

## Proof of concept

Steps against a local, self-hosted instance:

1. Install <PLUGIN> <VERSION> on WordPress <x.y>
2. Run:

```bash
<exact curl / HTTP request>
```

3. Observed result: <what proves exploitation — sleep delay, file contents,
   created admin user, etc.>

## Impact

What an attacker gains, concretely (data exposure, code execution, site
takeover chain, ...).

## Suggested remediation

- Wrap the query in `$wpdb->prepare()` / add `permission_callback` / add
  `current_user_can('...')` + `check_ajax_referer(...)` / use
  `esc_html__` / realpath-allowlist the path, etc. — one bullet per fix.

## Discoverer

<your name or handle> — <contact you want published with the CVE>
Reported via <Patchstack / Wordfence CNA / direct> on <YYYY-MM-DD>.
