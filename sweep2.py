#!/usr/bin/env python3
"""sweep2.py — class-based corpus sweep for the 250-plugin batch.

1. nopriv callback enumeration + write-op inventory (the sharpest class)
2. role escalation from request data
3. WooCommerce price tamper vectors
4. extract()/parse_str() variable pollution
5. weak token comparisons (== on secret-looking data)
6. raw move_uploaded_file (bypassing the WP upload API)
7. REST write routes guarded by weak capabilities
"""

import json
import os
import re
import subprocess

OUT = {}
NOPRIV = re.compile(r"add_action\s*\(\s*['\"]wp_ajax_nopriv_([\w\-]+)['\"]\s*,\s*['\"]?([\w\\\\]+)['\"]?\s*\)")
FUNC_RE = re.compile(r"\bfunction\s+(\w+)\s*\(")
WRITE_OPS = re.compile(r"\b(update_option|add_option|delete_option|update_user_meta|"
                       r"delete_user_meta|wp_insert_post|wp_update_post|wp_delete_post|"
                       r"wp_insert_user|wp_update_user|wp_set_password|file_put_contents|"
                       r"wp_mail|update_post_meta|delete_post_meta|wp_upload_bits|"
                       r"\$wpdb\s*->\s*(insert|update|delete))\b")

def spans_of(lines):
    spans, stack = [], None
    for i, l in enumerate(lines):
        if stack is None:
            m = FUNC_RE.search(l)
            if m:
                stack = {"name": m.group(1), "start": i, "depth": l.count("{") - l.count("}")}
        else:
            stack["depth"] += l.count("{") - l.count("}")
            if stack["depth"] <= 0:
                spans.append((stack["start"], i, stack["name"]))
                stack = None
    return spans

php_files = []
for root, _, names in os.walk("plugins"):
    for n in names:
        if n.endswith(".php"):
            php_files.append(os.path.join(root, n))

# ---------- 1. nopriv callbacks with write ops ----------
nopriv_hits = []
for path in php_files:
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    for m in NOPRIV.finditer(text):
        action, cb = m.group(1), m.group(2).split("\\")[-1]
        lines = text.splitlines()
        spans = spans_of(lines)
        target = [sp for sp in spans if sp[2].lower() == cb.lower()]
        if not target:
            continue  # callback in another file (class via array() syntax resolved later)
        s, e, fname = target[0]
        body = "\n".join(lines[s:e + 1])
        ops = sorted(set(WRITE_OPS.findall(body) and [x for x in WRITE_OPS.findall(body)]))
        # WRITE_OPS.findall returns tuples for the wpdb group; normalize
        flat = sorted(set(o if isinstance(o, str) else o[0] for o in ops)) if ops else []
        writes = []
        for w in flat:
            w = w if isinstance(w, str) else w[0]
            writes.append(w)
        if writes:
            nopriv_hits.append({
                "plugin": path.split("/")[1], "file": path.split("/", 2)[2],
                "line": s + 1, "action": action, "func": fname,
                "writes": [w for w in writes if w],
                "has_nonce_or_cap": bool(re.search(r"wp_verify_nonce|check_ajax_referer|current_user_can|get_transient|wp_hash|hash_equals|random_bytes", body)),
            })
OUT["nopriv_writes"] = nopriv_hits

# ---------- grep sweeps ----------
def rg(pattern, flags=""):
    p = subprocess.run(["rg", "--no-messages", "-n", pattern, "plugins"] + ([] if not flags else [flags]),
                       capture_output=True, text=True, timeout=300)
    return [l for l in p.stdout.splitlines() if l]

OUT["role_escalation"] = rg(r"(set_role|add_role|->roles\s*=\s*|wp_update_user[^\n]{0,80}role|update_user_meta\([^,]+, ?['\"]wp_capabilities)['\"])[^\n]{0,80}(\$_(POST|GET|REQUEST)|get_param)")
OUT["price_tamper"] = rg(r"\$_(POST|REQUEST|GET)\[['\"](price|amount|total|cost|subtotal)['\"]\]")
OUT["extract_pollution"] = rg(r"extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)")
OUT["parse_str_onearg"] = rg(r"parse_str\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\)")
OUT["weak_compare"] = rg(r"['\"]?(token|secret|hash|api_key|apikey|key|password)['\"]?\]?\s*==[^=]", "-g '!vendor/*'")
OUT["raw_move_uploaded"] = rg(r"move_uploaded_file\s*\(", "-g '!vendor/*'")
OUT["rest_weak_write"] = rg(r"CREATABLE|EDITABLE|DELETABLE", "-g '!vendor/*'")

json.dump(OUT, open("findings/sweep2.json", "w"), indent=1)

print(f"nopriv callbacks with WRITE ops: {len(nopriv_hits)}")
for h in nopriv_hits:
    flag = "" if h["has_nonce_or_cap"] else "  <<< NO GUARD TOKEN"
    print(f"  {h['plugin']} :: action={h['action']} {h['func']}() {h['file']}:{h['line']} writes={h['writes']}{flag}")
for k in ["role_escalation", "price_tamper", "extract_pollution", "parse_str_onearg"]:
    print(f"\n=== {k} ({len(OUT[k])}):")
    for l in OUT[k][:12]:
        print("  " + l[:170])
print(f"\n=== weak_compare ({len(OUT['weak_compare'])}) — top non-vendor:")
seen = 0
for l in OUT["weak_compare"]:
    if "/vendor/" in l:
        continue
    print("  " + l[:170]); seen += 1
    if seen > 14:
        break
print(f"\n=== raw_move_uploaded ({len(OUT['raw_move_uploaded'])}) — top non-vendor:")
seen = 0
for l in OUT["raw_move_uploaded"]:
    if "/vendor/" in l:
        continue
    print("  " + l[:170]); seen += 1
    if seen > 12:
        break
