#!/usr/bin/env python3
"""niche_hunt.py — resolve real slugs for wave candidates, filter the
under-the-radar zone (100-1000 installs, live, wave <= 2 recent CVEs).
Usage: python3 niche_hunt.py <from_idx> <to_idx>
"""
import json
import subprocess
import sys
import time
import urllib.parse

waves = json.load(open('/home/dev/wp-vuln-miner/findings/wave_candidates.json'))
a, b = int(sys.argv[1]), int(sys.argv[2])

OUT = '/home/dev/wp-vuln-miner/findings/niche_targets.json'
try:
    targets = json.load(open(OUT))
except Exception:
    targets = {}

# skip hardened (recent > 2) and giants (already known big names)
POOL = [w for w in waves if w['recent'] <= 2]
KNOWN_BIG = {'NEX-Forms – Ultimate Forms', 'Frontend Admin by DynamiApps', 'wpForo Forum',
             'Booking for Appointments and Events Calendar – Amelia', 'LearnPress',
             'WP Directory Kit', 'Form Maker by 10Web – Mobile-Friendly Drag & Drop Contact Form Builder',
             'The Events Calendar', 'Fluent Forms', 'Gravity Forms', 'Beaver Builder – WordPress Page Builder',
             'WPML Multilingual CMS', 'Slider Revolution', 'Smart Slider 3', 'Dokan Pro',
             'JetEngine', 'LearnDash LMS', 'Forminator Forms', 'Modula Image Gallery'}

for w in POOL[a:b]:
    name = w['name']
    if name in KNOWN_BIG:
        continue
    if name in targets:
        continue
    q = urllib.parse.quote(name[:60])
    url = ("https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&"
           f"request%5Bsearch%5D={q}&request%5Bper_page%5D=3")
    p = subprocess.run(["curl", "-g", "-s", "--connect-timeout", "10", "--max-time", "30", url],
                       capture_output=True, text=True)
    hit = None
    try:
        d = json.loads(p.stdout)
        for pl in d.get('plugins', []):
            nm = pl.get('name', '')
            if nm.lower().startswith(name.lower()[:18]):
                hit = pl
                break
            if not hit:
                hit = pl
    except Exception:
        pass
    if hit:
        inst = hit.get('active_installs') or 0
        targets[name] = {
            'slug': hit['slug'], 'installs': inst, 'version': hit.get('version'),
            'wave_recent': w['recent'], 'cwes': w['cwes'], 'last': max(m[0] for m in w['months']),
            'niche': 100 <= inst <= 1000,
        }
        print(f"{'*' if 100 <= inst <= 1000 else ' '} {hit['slug'][:46]:46s} inst={inst:>6} wave={w['recent']} {','.join(w['cwes'])}", flush=True)
    else:
        targets[name] = {'slug': None, 'not_found': True}
        print(f"  (not found) {name[:50]}", flush=True)
    json.dump(targets, open(OUT, 'w'), indent=0)
    time.sleep(3)

niches = [t for t in targets.values() if isinstance(t, dict) and t.get('niche')]
print(f"DONE {a}-{b}: niches so far = {len(niches)}")
