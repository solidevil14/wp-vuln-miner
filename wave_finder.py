#!/usr/bin/env python3
"""wave_finder.py — mid-wave vendor candidates.

Wave profile: 1-3 target-class CVEs published in the last 4 months,
NOT a hardened repeat-offender (<=3), extract the plugin display NAME
from the description for wporg keyword-search (real slug + installs).
"""
import json
import re
from collections import defaultdict

h = json.load(open('/home/dev/wp-vuln-miner/findings/nvd_harvest.json'))
HW = {'CWE-862', 'CWE-863', 'CWE-89', 'CWE-434', 'CWE-22', 'CWE-502'}
WAVE_MONTHS = {'2026-07', '2026-08', '2026-09', '2026-10'}

NAME_RE = re.compile(r"The\s+(?:\"|“)?([A-Za-z0-9 .\'’&/+–—-]+?)(?:\"|”)?\s+plugin\s+for\s+WordPress", re.I)

# map: display name -> [(month, cwe, cve, desc-snippet)]
byname = defaultdict(list)
for month, items in h.items():
    for it in items:
        if not (set(it['cwes']) & HW):
            continue
        m = NAME_RE.search(it['desc'])
        name = m.group(1).strip().rstrip('–-— ') if m else None
        if name:
            byname[name].append((it['published'][:7], ','.join(it['cwes']), it['cve'],
                                 it['desc'][:200]))

waves = []
for name, cves in byname.items():
    recent = [c for c in cves if c[0] in WAVE_MONTHS]
    if not (1 <= len(recent) <= 3):
        continue  # wave size: starting, not finished (hardened = 4+)
    months_active = sorted({c[0] for c in cves})
    waves.append({
        'name': name,
        'recent': len(recent),
        'total': len(cves),
        'months': months_active,          # spread = slow-patcher signal
        'cwes': sorted({c[1] for c in recent}),
        'latest_desc': cves[-1][3],
    })

# slow-patcher signal: CVEs spread across multiple months
waves.sort(key=lambda w: (-len(w['months']), -w['recent'], w['name']))
json.dump(waves, open('/home/dev/wp-vuln-miner/findings/wave_candidates.json', 'w'), indent=1)
print(f"{len(waves)} mid-wave candidates\n")
for w in waves[:30]:
    print(f"[recent={w['recent']} total={w['total']} months={len(w['months'])} {w['months'][0]}..{w['months'][-1]}] {w['name'][:56]}")
    print(f"     {','.join(w['cwes'])}  | {w['latest_desc'][:130]}")
