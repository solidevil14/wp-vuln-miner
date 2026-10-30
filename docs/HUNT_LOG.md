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

## Logic-pass round (logic_pass.py, same 250-plugin corpus)

- 102 raw candidates -> 80 after vendor/ filter -> 80 triaged by hand
- FP classes found & documented:
  * Freemius SDK `active_plugins` writes (bundled SDK, not per-plugin bugs)
  * `update_user_meta(get_current_user_id(), ...)` = own-id, not IDOR
  * diamond-sierra 2FA challenge deletion = re-challenge on next login,
    no bypass (annoyance DoS at most)
  * aluleth membership download: levels_of(0) = empty for guests, sane
  * slotvane ajax_import: nonce + manage_options + option-must-exist
  * abece privacy: bound to WP-core privacy officer caps + core nonces

**Batch-1 verdict: 0 confirmed 0-day / 250 plugins.** Fresh-plugin population
ships with modern guards (nonces, cap checks, token auth). Bug density lives
in the aged/popular-tail population -- batch 2 targets browse=updated.

## Sweep-2 round (sweep2.py + manual deep-dives, same corpus)

New sweeps: nopriv write-op inventory, role escalation, WC price tamper,
extract/parse_str pollution, weak token compares, raw move_uploaded_file,
REST weak caps, nopriv+userdata exposure.

~30 leads triaged by hand, deepest: elegant-profile-for-woocommerce
(self-built OTP auth: wp_rand + HMAC-hash + hash_equals + 5-try limit +
per-phone/IP throttles — clean), particod (manage_woocommerce +
order-bound nonce + GET_LOCK serialization — clean), bookingistic
(Capabilities::verify before payload — clean).

## BATCH-1 FINAL VERDICT

**250 plugins, 4 analysis layers, ~30 manual deep-dives: 0 confirmed
vulnerabilities.** The browse=new population ships with modern guards.
The bug-dense population is the aged one (browse=updated, half-maintained
2020-2022 plugins) — that is batch 2.

## Batch-2 small-slice rounds (per Kovak: little by little)

- slice A (modern aged): widget-for-eventbrite-api, picture-gallery,
  reepay, wgpwpp, skt-blocks, export-categories, upsell-order-bump,
  rss-feed-widget, product-blocks, formscrm — 251 findings, all FP
  (picture-gallery: guest uploads with per-form nonces + sha256 journal;
  upsell trio: template constants + manage_woocommerce+publish_pages)
- slice B (fossils >=7y): cp-multi-view-calendar, quick-event-manager,
  wp-easycart (1035 findings!), groundhogg, seo-booster, wp-plugin-info-card,
  seo-engine, shipping-zones-by-drawing, woo-exchange-rate, woc-open-close,
  admin-category-filter, wp-posts-carousel — all FP on manual read
  (cp-mvc: every path prepared or strtotime->date normalized; its documented
  design allows any front-end account to edit events — by design, not a bug)

Running total: ~50 plugins deep-dived, 0 confirmed. Code-level surface of
the reachable population is consistently defended. Strategy shift proposed:
known-vulnerable-slug adjacency hunting (audit same-author / same-genre code
around WPScan-listed CVE patterns).

## Adjacency round 2 (live repeat-offenders, small-batch tempo)

- wp-directory-kit + nex-forms: CLOSED on wporg, SVN wiped — code unavailable
- form-maker: Stripe webhook has no signature verification, BUT the route
  registers only in the premium build (is_free=1 hardcode) — dead for wporg
  scope (premium-only, unconfirmable without their code)
- all-in-one-video-gallery: hardened post-CVE (manage_aiovg_options + nonce)
- geo-mashup: clean (all echoes escaped)
- tainacan / wp-booking-system: triaged, clean surfaces

**FINDING #2 confirmed: WSDesk <= 1.7.0 (live)**
~30 admin-level AJAX handlers in class-crm-ajax-functions.php with zero
current_user_can and 3 nonces total. Destructive actions (single/multiple
ticket delete incl. bulk wipe, save_props, label/tag/field delete, agent
edit/remove) registered wp_ajax_* = any Subscriber. Plus CSRF (no nonce).
CWE-862 + CWE-352. CVSS ~8.1. Details in local disclosure/ (gitignored).
Public history carries only this redacted note.

## Install-filtered adjacency round (Kovak: filter yang ada usernya aja)

- install_map: top-48 ranked slugs checked against wporg API
- REAL slugs resolved: learnpress 70K, all-in-one-video-gallery 20K,
  wp-job-portal 8K, geo-mashup 1K, tainacan 1K, seo-booster 800,
  post-export-import 1K, the-events-calendar 600K, smart-slider-3 800K
- booking-calendar: wporg API now 404 = plugin CLOSED (post-CVE wave);
  zip still serves = stale installs; report still valid (Patchstack
  abandoned category) but flagship status downgraded
- learnpress 4.4.13: hardened (nonce+caps everywhere, 'Fix security' notes)
- wp-job-portal 2.7.2: hardened (per-method nonces, zywrap/copilot capped)
- form-maker: dead-end confirmed (is_free=1 hardcode, Stripe route
  registered only in premium build)

## Strategic conclusion (3rd repetition of the same pattern)

Vendors who just ate a CVE wave are hardened by audit time. The exploitable
window = vendors MID-WAVE (1-2 CVEs published, slow patcher, sibling bugs
not yet fixed). Existing assets: 2 confirmed findings (1 live-vendor
booking-calendar + 1 abandoned wsdesk), disclosure/ drafts ready for local
PoC verification + Patchstack submission.

## Mid-wave race, round 1 (Kovak picked B)

- wave_finder.py: 346 mid-wave candidates (1-3 CVEs in 2026-07..10)
- picked: TrueBooker (3 CVEs in 3 consecutive months, 600 installs, small)
  + LearnPress (70K) + wp-job-portal (8K) + tainacan re-audit
- TrueBooker 1.3.1: HARDENED — the 9-CVE wave forced class-level fixes
  (DB-ownership checks, server-side price validation); helper
  truebooker_require_customer_owner is real ownership; cart ops bound to
  visitor session
- LearnPress 4.4.13 + wp-job-portal 2.7.2: hardened
- tainacan re-audit: tmp_file traversal already patched in current

## Conclusion

Mid-wave window is narrow: Wordfence/Patchstack full-time researchers
hardened-wave vendors faster than a part-time audit cycle. Winning play =
weekly cadence (harvest diff -> wave_finder -> immediate audit), not
one-shot depth. Meanwhile: 2 confirmed findings await submission
(booking-calendar + wsdesk — both abandoned-track, both real).

## Rotting-hardening round (31 candidates from existing harvest, zero API waste)

- resolved real slugs: wp-ultimate-csv-importer 20K, wp-duplicate-page 60K,
  hippoo 1K, eyewear-prescription-form 10 (too small, skipped)
- wp-ultimate-csv-importer 9.3 (major rewrite post-7.37): hardened —
  sanitize_key upstream kills the hash_key interpolation, LogManager fully
  prepared, REST gated manage_options
- wp-duplicate-page 1.8.7: hardened (manage_options + custom cap njt_duplicate_page)

## FOURTH confirmation of the same pattern
Every researcher-visible wporg surface is already patched. The 0-day windows
that remain: (1) weekly mid-wave cadence, (2) <1000-install niche plugins
(pre-wave TrueBooker profile — CVE-assigned when found), (3) THEMES
(dramatically less audited than plugins), (4) premium/self-hosted products.

Assets on hand: 2 confirmed abandoned-track findings ready for Patchstack.

## Big-user hunt (Kovak: gas cari 0 day yang banyak penggunanya)

- Theme harvest (NVD 'wordpress theme', 6 months): 83 CVEs — the theme
  classes: password-reset takeover (Lenxel CWE-287, Nokri, Consulting),
  font-upload no-cap (Zella), unauth traversal downloads (Javo Spot,
  NativeChurch, ChurcHope), unauth object injection (Buzz Stone, Neo).
  All published = all being hammered.
- .org themes = FSE blocks (thin surface; auth flows live in companions)
- DnD Multiple File Upload CF7 (60K): quilted solid (3 patch rounds visible,
  Oct 2026 fixes — token+hash_equals+realpath everywhere)
- Mail Mint (7 CVEs, wave accelerating): checked TemplateAction ORDER BY
  (whitelisted), CampaignController IN() (intval upstream) — the checked
  spots are hardened; the vendor ships fixes weekly

## Session verdict on big-user 0-days
Big-install surfaces = a full-time race against Wordfence/Patchstack staff.
Wins need weekly cadence or the under-watched niches (<1K installs, themes'
companion plugins, premium). Two abandoned-track findings remain the
session's shippable assets.
