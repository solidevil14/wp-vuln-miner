#!/usr/bin/env python3
"""install_check.py — batch live/installs check for ranked candidate slugs.
Usage: python3 install_check.py <from_idx> <to_idx>
"""
import json
import subprocess
import sys
import time

slugs = json.load(open("/tmp/top48.json"))
a, b = int(sys.argv[1]), int(sys.argv[2])
try:
    out = json.load(open("/home/dev/wp-vuln-miner/findings/install_map.json"))
except Exception:
    out = {}

for s in slugs[a:b]:
    if s in out:
        continue
    url = ("https://api.wordpress.org/plugins/info/1.2/"
           f"?action=plugin_information&request%5Bslug%5D={s}")
    p = subprocess.run(["curl", "-g", "-s", "--connect-timeout", "10",
                        "--max-time", "30", url], capture_output=True, text=True)
    try:
        d = json.loads(p.stdout)
        out[s] = {"installs": d.get("active_installs"),
                  "last": str(d.get("last_updated"))[:10],
                  "version": d.get("version")}
        print(f"{s:55s} installs={out[s]['installs']} last={out[s]['last']}")
    except Exception:
        out[s] = {"installs": None, "last": None, "version": None, "dead": True}
        print(f"{s:55s} CLOSED/404")
    json.dump(out, open("/home/dev/wp-vuln-miner/findings/install_map.json", "w"), indent=0)
    time.sleep(3)
print("done", a, b)
