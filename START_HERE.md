# START HERE — run the whole hunt on YOUR machine

Everything in this repo is dependency-free Python 3.9+ and self-contained.
No sandbox walls: no timeouts, no flapping filesystem, real docker for the
dynamic PoC.

## 0. One-time setup

```bash
git clone https://github.com/solidevil14/wp-vuln-miner.git
cd wp-vuln-miner
mkdir -p plugins findings disclosure   # findings/ + disclosure/ ship empty-ish
```

Linux/macOS: everything works out of the box. Windows: use WSL2.

## 1. Refresh the CVE intelligence (5 min/week)

```bash
python3 nvd_harvest.py           # monthly windows, incremental, ~15 min first run
python3 wave_finder.py           # mid-wave candidates from the harvest
```

Wave profile: vendors with 1-3 CVEs in the last months = still bleeding =
the exploitable window. `findings/wave_candidates.json` = the ranked list.

## 2. Build the target queue (2 min)

```bash
python3 niche_hunt.py 0 40       # resolves real slugs + installs via wporg search
```

Filter targets: `niche: true` = 100–1.000 installs (below the researcher
radar — the TrueBooker zone: that one had 9 CVEs nobody touched).

## 3. Download + scan a batch (5 min/batch)

```bash
python3 fetch_plugins.py --slugs slug1,slug2,slug3 --download 3
python3 scan.py --plugins-dir plugins --out findings
python3 deep_pass.py             # 1-indirection taint tracking
python3 logic_pass.py            # IDOR / weak-cap / option-poisoning
python3 sweep2.py                # class sweeps (nopriv writes, price, roles)
```

Read `findings/REPORT.md` — everything ≥ 7.0 needs your eyes.
FULL triage discipline in `docs/HUNT_LOG.md` (read the FP lessons first —
they save you the same dead-ends this session hit: prepared-wrapping,
first-arg SSRF taint, full-span guards, vendor SDKs).

## 4. Verify a finding dynamically (the step that makes it a CVE)

```bash
cd disclosure
docker compose up -d             # WP + MariaDB on :8080
# install the plugin: copy from ../plugins/<slug> into the wp volume:
docker compose exec wpcli bash -c "cp -r /srv-plugins/<slug> /var/www/html/wp-content/plugins/ && wp plugin activate <slug> --allow-root"
# complete WP install at http://localhost:8080, then follow the PoC files.
```

A finding is REPORT-READY only when the PoC runs against your local docker.

## 5. Report (Patchstack = the CVE path)

1. Account at patchstack.com → Report a vulnerability (free)
2. Use `docs/report_template.md` — one plugin, one flaw per report
3. They triage (1–7 d) → contact the vendor → patch → **CVE assigned** (30–90 d)
4. Abandoned/closed plugins: same form, same CVE path, longer timeline
5. Full playbook: `docs/CVE_PATH.md`

## 6. After the CVE lands

- Publish the PoC repo (redact until the disclosure date)
- Write the Suricata rule for the exploit signatures (your detections repo)

## The four windows (proven this session — see docs/HUNT_LOG.md)

1. **Weekly cadence** — mid-wave vendors, audit < 48 h after their first CVE
2. **< 1K installs** — below the researcher radar, still CVE-assigned
3. **Themes' companion plugins** — the theme CVE class is hot (83 in 6 months)
4. **Premium products** — no .org scrubbing

## The two findings already in hand (disclosure/ — LOCAL ONLY, not committed)

- **0day-1-booking-calendar.md** — PayPal IPN `VERIFIED` never checked (7.7)
- **0day-3-wsdesk.md** — missing authz on ~30 AJAX actions + CSRF (8.1)
- `docker-compose.yml` + `verify.sh` = the lab

Report those FIRST. Then run the weekly loop.
