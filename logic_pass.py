#!/usr/bin/env python3
"""logic_pass.py — logic-bug detectors (the classes that actually dominate
WP plugin CVEs): IDOR / missing-ownership, weak capability gates, option
poisoning. Function-span based, hook-context aware.

Run after (or instead of) scan.py. Output: findings/logic_candidates.json
"""

import json
import os
import re

MAX_FILE = 1_000_000

HOOK_RES = [
    (re.compile(r"""add_action\s*\(\s*['"]wp_ajax_nopriv_([\w\-]+)"""), "nopriv"),
    (re.compile(r"""add_action\s*\(\s*['"]wp_ajax_([\w\-]+)"""), "logged"),
    (re.compile(r"""add_action\s*\(\s*['"]admin_post_nopriv_([\w\-]+)"""), "nopriv"),
    (re.compile(r"""add_action\s*\(\s*['"]admin_post_([\w\-]+)"""), "logged"),
    (re.compile(r"""add_action\s*\(\s*['"]rest_api_init"""), "rest"),
]
FUNC_RE = re.compile(r"\bfunction\s+(\w+)\s*\(")
REQUEST = re.compile(r"\$_(GET|POST|REQUEST|COOKIE)\b|get_param\s*\(|get_json_params\s*\(|->get_body\s*\(")

OWNERSHIP = re.compile(
    r"current_user_can\s*\([^,)]+,\s*\$|post_author\s*===?\s*|===?\s*.*post_author|"
    r"user_id\s*===?\s*.*get_current_user_id\(\)|get_current_user_id\(\)\s*===?\s*|"
    r"wc_get_order_customer|belongs_to|->author\s*!==?\s*|!==?\s*.*->author"
)
STATE_CHANGE_1ARG = [
    ("idor_meta", re.compile(r"\b(update_user_meta|delete_user_meta|update_user_option|delete_user_option|wp_update_user)\s*\(")),
    ("idor_post", re.compile(r"\b(wp_delete_post|wp_trash_post|wp_update_post|delete_post_meta|update_post_meta|wp_set_post_terms|set_post_thumbnail)\s*\(")),
    ("idor_db", re.compile(r"\$wpdb\s*->\s*(update|delete)\s*\(")),
]
WEAK_CAPS = re.compile(r"current_user_can\s*\(\s*['\"](read|upload_files|read_private_posts)['\"]\s*\)")
LONE_LOGIN = re.compile(r"\bis_user_logged_in\s*\(\s*\)")
CAP_ANY = re.compile(r"current_user_can\s*\(")
NONCE_ANY = re.compile(r"wp_verify_nonce|check_ajax_referer|check_admin_referer|current_user_can")

CRITICAL_OPTS = re.compile(r"update_option\s*\(\s*['\"](siteurl|home|users_can_register|default_role|admin_email|template|stylesheet|active_plugins|upload_path|option_[a-z_]*role)['\"]")
OPT_VAR = re.compile(r"update_option\s*\(\s*(\$\w+)")

METHODS = re.compile(r"\bfunction\s+\w+")


def function_spans(lines):
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


def scan_file(plugin, path, out):
    try:
        if os.path.getsize(path) > MAX_FILE:
            return
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return
    if "<?php" not in text:
        return
    lines = text.splitlines()
    hooks = []
    for rx, auth in HOOK_RES:
        for m in rx.finditer(text):
            hooks.append((auth, text[:m.start()].count("\n")))
    spans = function_spans(lines)

    for (s, e, fname) in spans:
        if "/vendor/" in path.replace("\\", "/"):
            return  # bundled SDKs (freemius et al) are not per-plugin bugs
        body = "\n".join(lines[s:e + 1])
        rel = os.path.relpath(path, os.path.join("plugins", plugin))
        auth = "unknown"
        for a, hl in hooks:
            if s <= hl <= e:
                auth = a
                break

        req_var_lines = []
        for j in range(s, e + 1):
            if REQUEST.search(lines[j]):
                req_var_lines.append(j)

        # collect request-derived vars (direct or via simple assignment)
        tvars = set()
        for j in range(s, e + 1):
            l = lines[j]
            m = re.search(r"\$(\w+)\s*=\s*[^;]*(" + REQUEST.pattern + ")", l)
            if m:
                tvars.add("$" + m.group(1))
            for dm in re.finditer(r"\$_(?:GET|POST|REQUEST|COOKIE)\[['\"]?(\w+)['\"]?\]", l):
                tvars.add("$_*[" + dm.group(1) + "]")

        def has_ownership():
            return bool(OWNERSHIP.search(body))

        for dname, rx in STATE_CHANGE_1ARG:
            m = rx.search(body)
            if not m:
                continue
            # does the call site touch a request-derived id within 3 lines?
            hit = False
            for j in range(s, e + 1):
                if rx.search(lines[j]):
                    win = "\n".join(lines[j:j + 4])
                    if any(t in win for t in tvars):
                        hit = True
                        break
            if not hit:
                continue
            guarded = has_ownership()
            weak = bool(WEAK_CAPS.search(body)) or (bool(LONE_LOGIN.search(body)) and not CAP_ANY.search(body))
            if auth == "nopriv" and not guarded:
                sev = 8.6 if dname != "idor_db" else 8.2
            elif auth in ("logged", "rest") and not guarded:
                sev = 6.5 if dname != "idor_db" else 6.0
            elif auth == "unknown" and not guarded:
                sev = 5.5
            else:
                continue
            if weak:
                sev = min(sev + 1.0, 9.5)
            if NONCE_ANY.search(body) and auth != "nopriv":
                sev -= 0.5  # some guard present, likely fine-ish
            if sev < 5.0:
                continue
            ev = next((lines[j].strip()[:150] for j in range(s, e + 1) if rx.search(lines[j])), "")
            out.append({"plugin": plugin, "file": rel, "line": s + 1, "class": dname,
                        "func": fname, "auth": auth, "severity": round(sev, 1),
                        "evidence": ev, "tainted": sorted(tvars)[:6]})

        # option poisoning
        m = CRITICAL_OPTS.search(body) or (OPT_VAR.search(body) and any(
            "$" + OPT_VAR.search(body).group(1)[1:] in b for b in [body]) and OPT_VAR.search(body).group(1) in body and False)
        m2 = OPT_VAR.search(body)
        if m2 and not re.search(r"update_option\s*\(\s*['\"]", body):
            # first arg is a variable that is request-derived
            for j in range(s, e + 1):
                if OPT_VAR.search(lines[j]) and any(t in lines[j] for t in tvars):
                    out.append({"plugin": plugin, "file": rel, "line": j + 1, "class": "option_poison",
                                "func": fname, "auth": auth, "severity": 8.0 if auth == "nopriv" else 6.0,
                                "evidence": lines[j].strip()[:150], "tainted": sorted(tvars)[:6]})
                    break
        elif m:
            out.append({"plugin": plugin, "file": rel, "line": s + 1, "class": "option_poison",
                        "func": fname, "auth": auth, "severity": 8.0 if auth == "nopriv" else 6.0,
                        "evidence": m.group(0), "tainted": []})


def main():
    out = []
    for plugin in sorted(os.listdir("plugins")):
        root = os.path.join("plugins", plugin)
        if not os.path.isdir(root):
            continue
        for dirpath, _, files in os.walk(root):
            for f in files:
                if f.endswith(".php"):
                    scan_file(plugin, os.path.join(dirpath, f), out)
    os.makedirs("findings", exist_ok=True)
    json.dump(out, open("findings/logic_candidates.json", "w"), indent=1)
    out.sort(key=lambda x: -x["severity"])
    print(f"{len(out)} logic candidates")
    for c in out[:35]:
        print(f"[{c['severity']}] {c['class']} {c['plugin']} {c['file']}:{c['line']} "
              f"{c['func']}() auth={c['auth']}")
        print(f"      {c['evidence'][:130]}")


if __name__ == "__main__":
    main()
