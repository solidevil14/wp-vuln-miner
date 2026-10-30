#!/usr/bin/env python3
"""fetch_plugins.py — pull the wordpress.org plugin catalog, filter the sweet
spot (new / low-install / recently maintained), download and extract zips.

Usage:
  python3 fetch_plugins.py --browse new --pages 2 --max-installs 3000 --download 10
  python3 fetch_plugins.py --slugs some-plugin,another --download 2
"""

import argparse
import io
import json
import os
import re
import sys
import time
import urllib.request
import urllib.parse
import zipfile

API = "https://api.wordpress.org/plugins/info/1.2/"
UA = "wp-vuln-miner/0.1 (security research; local audit only)"


def http_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=45) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def query_plugins(browse, page, per_page):
    q = urllib.parse.urlencode({
        "action": "query_plugins",
        "request[per_page]": per_page,
        "request[browse]": browse,
        "request[page]": page,
    })
    return http_json(f"{API}?{q}")


def days_since(datestr):
    if not datestr:
        return 9999
    m = re.match(r"(\d{4}-\d{2}-\d{2})", str(datestr))
    if not m:
        return 9999
    import datetime
    return (datetime.date.today() - datetime.date.fromisoformat(m.group(1))).days


def download_and_extract(slug, url, outdir):
    pdir = os.path.join(outdir, slug)
    if os.path.isdir(pdir) and os.listdir(pdir):
        return pdir, "cached"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            data = r.read()
    except Exception as e:
        return None, f"download-failed: {e}"
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            z.extractall(outdir)  # archives contain <slug>/... root
    except zipfile.BadZipFile:
        return None, "bad-zip"
    return pdir, "ok"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--browse", default="new", choices=["new", "updated", "popular"])
    ap.add_argument("--pages", type=int, default=1)
    ap.add_argument("--per-page", type=int, default=100)
    ap.add_argument("--min-installs", type=int, default=0)
    ap.add_argument("--max-installs", type=int, default=3000)
    ap.add_argument("--max-age-days", type=int, default=365,
                    help="only plugins updated within this window (maintainer alive)")
    ap.add_argument("--download", type=int, default=0,
                    help="download N plugins from the filtered set (0 = manifest only)")
    ap.add_argument("--slugs", default="", help="comma-separated specific slugs")
    ap.add_argument("--outdir", default="plugins")
    ap.add_argument("--manifest", default="manifest.json")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    manifest_path = os.path.join(os.path.dirname(args.manifest) or ".", args.manifest)
    manifest = {}
    if os.path.exists(manifest_path):
        manifest = json.load(open(manifest_path))

    pool = []
    if args.slugs:
        pool = [{"slug": s.strip(), "name": s.strip(), "version": "?",
                 "active_installs": None, "last_updated": None,
                 "download_link": f"https://downloads.wordpress.org/plugin/{s.strip()}.latest-stable.zip"}
                for s in args.slugs.split(",") if s.strip()]
    else:
        for page in range(1, args.pages + 1):
            try:
                data = query_plugins(args.browse, page, args.per_page)
            except Exception as e:
                print(f"[!] page {page} failed: {e}", file=sys.stderr)
                break
            for p in (data.get("plugins") or []):
                inst = p.get("active_installs") or 0
                if not (args.min_installs <= inst <= args.max_installs):
                    continue
                if days_since(p.get("last_updated")) > args.max_age_days:
                    continue
                pool.append(p)
            print(f"[*] page {page}: pool={len(pool)}")

    new = [p for p in pool if p["slug"] not in manifest]
    for p in pool:  # refresh metadata for known ones
        if p["slug"] in manifest:
            manifest[p["slug"]].update({k: p.get(k) for k in
                                        ("version", "active_installs", "last_updated")})
    print(f"[*] filtered pool: {len(pool)} ({len(new)} new)")

    n_dl = 0
    for p in pool:
        if p["slug"] in manifest and manifest[p["slug"]].get("status") == "ok":
            continue  # already downloaded in a previous run
        if n_dl >= args.download and args.download > 0:
            break
        slug = p["slug"]
        pdir, status = download_and_extract(slug, p["download_link"], args.outdir)
        if status == "ok":
            n_dl += 1
        manifest[slug] = {
            "name": p.get("name"), "version": p.get("version"),
            "active_installs": p.get("active_installs"),
            "last_updated": p.get("last_updated"),
            "download_link": p.get("download_link"),
            "dir": pdir, "status": status,
        }
        print(f"  [{status}] {slug} (installs={p.get('active_installs')})")
        time.sleep(1.0)  # be polite to the CDN

    json.dump(manifest, open(manifest_path, "w"), indent=1)
    print(f"[*] manifest -> {manifest_path} ({len(manifest)} plugins total, {n_dl} downloaded)")


if __name__ == "__main__":
    main()
