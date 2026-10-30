#!/usr/bin/env python3
"""scan.py — static taint-pattern scanner for WordPress plugins.

Finds hook-context + source -> sink flows across the vuln classes that
dominate WP plugin CVEs: SQLi, RCE, deserialization, arbitrary file
read/write/delete, SSRF, open redirect, XSS, missing authz.

Usage:
  python3 scan.py --plugins-dir plugins --out findings
"""

import argparse
import json
import os
import re

MAX_FILE = 1_000_000

HOOK_RES = [
    (re.compile(r"""add_action\s*\(\s*['"]wp_ajax_nopriv_([\w\-]+)"""), "nopriv"),
    (re.compile(r"""add_action\s*\(\s*['"]wp_ajax_([\w\-]+)"""), "logged"),
    (re.compile(r"""add_action\s*\(\s*['"]admin_post_nopriv_([\w\-]+)"""), "nopriv"),
    (re.compile(r"""add_action\s*\(\s*['"]admin_post_([\w\-]+)"""), "logged"),
]

FUNC_RE = re.compile(r"\bfunction\s+(\w+)\s*\(")
AUTHZ_RE = re.compile(r"\b(current_user_can|wp_verify_nonce|check_ajax_referer|"
                      r"check_admin_referer|is_user_logged_in)\s*\(")
SANITIZERS = re.compile(r"\b(intval|absint|sanitize_key|sanitize_text_field|"
                        r"sanitize_title|esc_sql|wp_unslash|floatval)\s*\(")

SINKS = [
    ("rce", re.compile(r"\b(eval|assert|create_function|system|exec|shell_exec|"
                       r"passthru|popen|proc_open)\s*\(")),
    ("sqli", re.compile(r"\$wpdb\s*->\s*(query|get_results|get_row|get_var|get_col)\s*\(")),
    ("unserialize", re.compile(r"\b(maybe_unserialize|unserialize)\s*\(")),
    ("file", re.compile(r"\b(file_get_contents|readfile|fopen|fread|file|unlink|rmdir|"
                        r"file_put_contents|copy|rename|move_uploaded_file|"
                        r"ZipArchive->extractTo|include_once|require_once|include|require)\b")),
    ("ssrf", re.compile(r"\b(wp_remote_get|wp_remote_post|wp_remote_request|curl_exec|"
                        r"wp_safe_remote_get)\s*\(")),
    ("redirect", re.compile(r"\b(wp_redirect)\s*\(")),
    ("xss", re.compile(r"\b(echo|print)\b[^;]*\$")),
]

SOURCES = re.compile(r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|php://input")

VAR_ASSIGN = re.compile(r"(\$\w+)\s*=\s*([^;]+);")


def file_hooks(text):
    """Map callback function name -> auth context from hook registrations."""
    hooks = []
    for rx, auth in HOOK_RES:
        for m in rx.finditer(text):
            # callback is the next quoted string after the hook name
            tail = text[m.end(): m.end() + 200]
            cb = re.search(r"""['"]([\w\\\\]+)['"]""", tail)
            hooks.append((cb.group(1).split("\\")[-1] if cb else None, auth,
                          text[:m.start()].count("\n") + 1))
    return hooks


def rest_routes(text):
    """register_rest_route blocks without a real permission_callback."""
    out = []
    for m in re.finditer(r"register_rest_route\s*\(", text):
        chunk = text[m.end(): m.end() + 1500]
        if "permission_callback" not in chunk:
            out.append(("REST-no-permission_callback", "nopriv",
                        text[:m.start()].count("\n") + 1))
        elif re.search(r"permission_callback['\"\s]*=>\s*__return_true", chunk):
            out.append(("REST-permission=__return_true", "nopriv",
                        text[:m.start()].count("\n") + 1))
    return out


def scan_file(plugin, root, rel, findings):
    path = os.path.join(root, rel)
    try:
        if os.path.getsize(path) > MAX_FILE:
            return
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return
    if "<?php" not in text:
        return

    hooks = file_hooks(text) + rest_routes(text)
    lines = text.splitlines()

    # crude alias map: $var = <expr containing a source>
    aliases = set()
    for m in VAR_ASSIGN.finditer(text):
        if SOURCES.search(m.group(2)):
            aliases.add(m.group(1))

    func_spans = []  # (start_line, name)
    for i, ln in enumerate(lines):
        fm = FUNC_RE.search(ln)
        if fm:
            func_spans.append((i, fm.group(1)))

    def auth_for(line_no, fname):
        best, bestd = "unknown", 10**9
        for cb, auth, hline in hooks:
            if cb and (cb == fname or fname and fname.lower() == cb.lower()):
                d = abs(line_no - hline)
                if d < bestd:
                    best, bestd = auth, d
        return best

    for lineno, line in enumerate(lines, 1):
        for cls, rx in SINKS:
            m = rx.search(line)
            if not m:
                continue
            # sqli: prepared statements are fine — skip when prepare() wraps it
            if cls == "sqli" and ("->prepare(" in line or "prepare(" in line):
                continue
            # taint: superglobal/alias/parsed-input token on the line or in the
            # 5 lines above (short chaining), and no obvious sanitizer right there
            ctx = "\n".join(lines[max(0, lineno - 6): lineno])
            tainted = bool(SOURCES.search(line)) or any(a in line for a in aliases) \
                or bool(SOURCES.search(ctx)) or any(a in ctx for a in aliases)
            if not tainted:
                continue
            fname = ""
            fstart = 0
            for fs, nm in reversed(func_spans):
                if fs < lineno:
                    fname, fstart = nm, fs
                    break
            auth = auth_for(lineno, fname)
            if cls in ("ssrf", "redirect", "file"):
                # URL/path sinks need the taint on the sink line itself
                if not (SOURCES.search(line) or any(a in line for a in aliases)):
                    continue
                if cls == "ssrf":
                    # only the FIRST argument (the URL) counts as the taint target
                    first_arg = line[m.end(): line.find(",", m.end()) if line.find(",", m.end()) != -1 else len(line)]
                    if not (SOURCES.search(first_arg) or any(a in first_arg for a in aliases)):
                        continue
            chunk = text[max(0, text.find(fname) if fname else 0):].split("function", 1)
            guard_zone = lines[fstart:lineno - 1] if fstart else lines[max(0, lineno - 25): lineno]
            guarded = any(AUTHZ_RE.search(g) for g in guard_zone)
            sanitized = bool(SANITIZERS.search(line))
            sev = {"rce": 9.8, "unserialize": 8.8, "file": 8.5, "sqli": 8.5,
                   "ssrf": 7.5, "redirect": 6.5, "xss": 5.0}[cls]
            if auth == "nopriv":
                sev = min(sev + 1.0, 10.0)
            elif auth == "admin":
                sev -= 3.0
            if guarded:
                sev -= 2.0
            if sanitized:
                sev -= 2.5
            if sev < 3.0:
                continue
            findings.append({
                "plugin": plugin, "file": rel, "line": lineno, "class": cls,
                "function": fname, "auth": auth, "severity": round(max(sev, 1.0), 1),
                "hook_context": [h for h in hooks if h[0] == fname],
                "snippet": line.strip()[:200],
            })
            break  # one class per line


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plugins-dir", default="plugins")
    ap.add_argument("--out", default="findings")
    args = ap.parse_args()

    findings = []
    scanned = 0
    for plugin in sorted(os.listdir(args.plugins_dir)):
        root = os.path.join(args.plugins_dir, plugin)
        if not os.path.isdir(root):
            continue
        for dirpath, _, files in os.walk(root):
            for f in files:
                if f.endswith(".php"):
                    rel = os.path.relpath(os.path.join(dirpath, f), root)
                    before = len(findings)
                    scan_file(plugin, root, rel, findings)
                    if len(findings) > before:
                        scanned += 1
        print(f"[*] {plugin}: {sum(1 for x in findings if x['plugin'] == plugin)} findings")

    os.makedirs(args.out, exist_ok=True)
    json.dump(findings, open(f"{args.out}/findings.json", "w"), indent=1)

    findings.sort(key=lambda x: -x["severity"])
    with open(f"{args.out}/REPORT.md", "w") as fh:
        fh.write("# Triage report\n\n")
        top = [f for f in findings if f["severity"] >= 7.0]
        fh.write(f"**{len(findings)} findings, {len(top)} worth manual review**\n\n")
        cur = None
        for f in findings:
            if f["severity"] < 3.0:
                continue
            if f["plugin"] != cur:
                cur = f["plugin"]
                fh.write(f"\n## {cur}\n\n")
            fh.write(f"- **[{f['severity']}] {f['class'].upper()} / {f['auth']}** "
                     f"`{f['file']}:{f['line']}` in `{f['function']}()`")
            fh.write(f"\n  - hook: {f['hook_context']}\n")
            fh.write(f"\n  ```php\n  {f['snippet']}\n  ```\n")
    print(f"[*] {len(findings)} findings -> {args.out}/REPORT.md")


if __name__ == "__main__":
    main()
