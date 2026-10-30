# Hunt log — batch 1 (250 plugins, browse=new, installs<=3000)

- line-scan findings: 1855
- deep-dataflow candidates: 2
- direct superglobal->sink one-liners: 0
- confirmed 0-day: 0 (all top-tier leads were false positives on manual read)

## FP lessons encoded into the scanner
1. `$wpdb->query($wpdb->prepare(...))` across two lines — prepare-tracked aliases
2. SSRF taint in arg-2 (headers/body) while URL is constant — first-arg rule
3. guards beyond a 25-line window — full function span
4. `maybe_unserialize($option_value)` from DB = standard WP pattern, not taint
5. marchnote/sarala-class plugins: properly token-nonce-gated — clean write-ups of why they're NOT vulns live in this log

## Next batches
- volume: 1000+ plugins, --browse updated (higher bug density than new)
- new detectors planned: nonce-action mismatch, ownership-check-missing
  IDORs (object access by raw ID), option-value poisoning, cap-map mismatch
