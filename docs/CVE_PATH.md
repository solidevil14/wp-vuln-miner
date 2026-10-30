# CVE assignment path for WordPress plugins

The practical reality as of 2026: you cannot request a CVE directly from
MITRE as an individual. WordPress plugin CVEs are assigned by CNAs. Two
routes dominate, both free:

## Route 1 — Patchstack (recommended default)

1. Account at patchstack.com → "Report a vulnerability" (free tier).
2. Submit the report from `report_template.md`. They triage (usually 1–7 days).
3. They contact the plugin author (private channel) and handle coordination.
4. Once the vendor patches and the update ships to wordpress.org, Patchstack
   assigns the CVE through their CNA. Typical total: 30–90 days.
5. Bonus: their bug bounty pool pays for valid in-wildlife reports (modest:
   ~$50–$350 depending on severity and plugin popularity).
6. You pick the public credit name/handle; it's embedded in the advisory.

## Route 2 — Wordfence CNA

Same flow, report at wordfence.com → vulnerability disclosure. They also run
a bounty program and assign CVEs for wordpress.org plugins. Their strength:
fast triage; weakness: they prioritize plugins in their customer-relevant set.

## Route 3 — direct to vendor (for reachable, responsive authors)

The plugin's readme.txt / plugin page lists a support/email contact. For
small plugins the author often responds within days. After the fix is
pushed to the SVN trunk and released, request the CVE from Patchstack or
Wordfence referencing the fixed version (they assign for already-public
issues too — mark it as "already patched, requesting ID").

## Hard rules (keeps you clean and the CVE valid)

- Audit only GPL code downloaded from wordpress.org — legal, by design.
- Test ONLY against a local instance you own (docker-compose).
- No automated probing of live third-party sites — that's the line where a
  research project becomes an incident. The PoC runs against localhost.
- Coordinate before public disclosure: no public writeup before the patch
  ships and the CVE is reserved (standard is 90 days from report, often
  shorter for WP).
- One plugin + one flaw per report; don't bundle.

## After the CVE lands

- Advisory + PoC repo (redacted until disclosure date).
- Then feed it the same pipeline as before: WPScan entry, Patchstack DB,
  and if you want, a Suricata rule for your detections repo — the exploit
  request signatures (unique param names, action hooks) make clean rules.
