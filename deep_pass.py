#!/usr/bin/env python3
"""deep_pass.py — second-stage mini-dataflow over the corpus.

Finds sinks whose argument variable was BUILT via concatenation (or .=)
from request-derived data, with no prepare() anywhere in the build chain.
This catches the one-indirection cases the line-based scanner misses.
"""

import json
import os
import re

FUNC = re.compile(r"\bfunction\s+(\w+)\s*\(")
REQUEST = re.compile(r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\b|wp_unslash\s*\(")
PREPARE = re.compile(r"->prepare\s*\(|esc_sql\s*\(|\$wpdb\s*->\s*prepare")
ASSIGN = re.compile(r"^\s*(\$\w+)\s*(\.\?=|=|\.=)\s*(.+?);\s*(//.*)?$")
SINKS = [
    ("sqli", re.compile(r"\$wpdb\s*->\s*(query|get_results|get_row|get_var|get_col)\s*\(\s*(\$\w+)")),
    ("include", re.compile(r"\b(include|require)(_once)?\s*\(?\s*(\$\w+)")),
    ("file", re.compile(r"\b(file_get_contents|readfile|fopen|unlink)\s*\(\s*(\$\w+)")),
    ("rce", re.compile(r"\b(eval|assert|system|exec|shell_exec|passthru)\s*\(\s*(\$\w+)")),
]

files = []
for root, _, names in os.walk("plugins"):
    for n in names:
        if n.endswith(".php"):
            files.append(os.path.join(root, n))

cands = []
for path in files:
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    if "<?php" not in text:
        continue
    lines = text.splitlines()
    func_starts = [(i, FUNC.search(l).group(1)) for i, l in enumerate(lines) if FUNC.search(l)]

    def enclosing(i):
        name = "(top)"
        for fs, nm in func_starts:
            if fs <= i:
                name = nm
        return name

    # assignment map: var -> set of lines where built
    builds = {}
    prepared = set()
    for i, l in enumerate(lines):
        m = ASSIGN.match(l)
        if not m:
            continue
        var, _, rhs = m.group(1), m.group(2), m.group(3)
        builds.setdefault(var, []).append((i, rhs))
        if PREPARE.search(rhs) or PREPARE.search(l):
            prepared.add(var)

    seen = set()
    for i, l in enumerate(lines):
        for cls, rx in SINKS:
            m = rx.search(l)
            if not m:
                continue
            sinkvar = m.groups()[-1]
            chain = builds.get(sinkvar, [])
            if not chain or sinkvar in prepared:
                continue
            # the build chain must contain request data directly or via a
            # request-tainted variable, and at least one concatenation
            tainted = False
            for bline, rhs in chain:
                if REQUEST.search(rhs):
                    tainted = True
                # var-to-var spread: $a = $req_var (single var rhs)
                vm = re.match(r"\s*(\$\w+)\s*$", rhs)
                if vm and vm.group(1) in builds:
                    for _, rhs2 in builds[vm.group(1)]:
                        if REQUEST.search(rhs2):
                            tainted = True
            if not tainted:
                continue
            key = (path, i, cls)
            if key in seen:
                continue
            seen.add(key)
            cands.append({
                "plugin": path.split("/")[1], "file": "/".join(path.split("/")[2:]),
                "line": i + 1, "class": cls, "func": enclosing(i),
                "build": [f"L{b+1}: {r.strip()[:110]}" for b, r in chain[:4]],
                "sink": l.strip()[:110],
            })

json.dump(cands, open("findings/deep_candidates.json", "w"), indent=1)
print(f"{len(cands)} deep candidates")
for c in cands[:40]:
    print(f"[{c['class']}] {c['plugin']} {c['file']}:{c['line']} in {c['func']}()")
    for b in c["build"]:
        print("     build:", b)
    print("     SINK :", c["sink"])
