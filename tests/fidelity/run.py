#!/usr/bin/env python3
"""Run the fidelity round trip over the whole corpus and print a table.

For each file in tests/corpus/corpus.json: keepass-rs opens it, edits one
title (history-tracked) and saves KDBX 4 (roundtrip.rs); pykeepass compares
before and after (compare.py). Full reports land in tests/fidelity/out/.
A file may carry `expect` in corpus.json: findings already known and written
up in docs/SPIKE-0.md. Exit status is 0 only when nothing else shows up.
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
CORPUS = os.path.join(REPO, "tests", "corpus")
OUT = os.path.join(HERE, "out")
BIN = os.path.join(REPO, "target", "release", "examples", "fidelity-roundtrip")


def generator(path, pw, kf):
    from pykeepass import PyKeePass
    kp = PyKeePass(path, password=pw, keyfile=kf)
    return kp.tree.findtext("Meta/Generator") or "?", "%d.%d" % kp.version


def main():
    os.makedirs(OUT, exist_ok=True)
    subprocess.run(["cargo", "build", "--release", "-q", "-p", "safe-core", "--example", "fidelity-roundtrip"],
                   cwd=REPO, check=True)
    corpus = json.load(open(os.path.join(CORPUS, "corpus.json")))
    rows, bad = [], 0
    for f in corpus["files"]:
        src = os.path.join(CORPUS, "files", f["source"], f["file"])
        kf = os.path.join(CORPUS, "files", f["source"], f["keyfile"]) if f.get("keyfile") else None
        pw = f["password"]
        stem = "%s__%s" % (f["source"], f["file"])
        dst = os.path.join(OUT, stem)
        writer, ver = generator(src, pw, kf)
        argv = [BIN, "--in", src, "--out", dst, "--password", pw] + (["--keyfile", kf] if kf else [])
        expect = f.get("expect", {})
        r = subprocess.run(argv, capture_output=True, text=True)
        if r.returncode != 0:
            err = (r.stderr.strip().splitlines() or ["?"])[-1]
            if expect.get("open_fails") and expect["open_fails"] in err:
                rows.append((stem, writer, ver, "-", "known: keepass-rs refuses to open (" + expect["open_fails"] + ")"))
            else:
                rows.append((stem, writer, ver, "-", "NEW: save failed: " + err))
                bad += 1
            continue
        rt = json.loads(r.stdout)
        cmp_argv = [sys.executable, "-I", os.path.join(HERE, "compare.py"), src, dst, "--password", pw,
                    "--edited", json.dumps(rt["edited"])] + (["--keyfile", kf] if kf else [])
        c = subprocess.run(cmp_argv, capture_output=True, text=True)
        if c.returncode != 0:
            rows.append((stem, writer, ver, rt["out_version"], "COMPARE FAILED: " + (c.stderr.strip().splitlines() or ["?"])[-1]))
            bad += 1
            continue
        rep = json.loads(c.stdout)
        rep["roundtrip"] = rt
        json.dump(rep, open(dst + ".json", "w"), ensure_ascii=False, indent=1)
        known = []
        for kind in ("lost", "changed", "added"):
            pats = expect.get(kind, [])
            rest = [x for x in rep[kind] if not any(p in x for p in pats)]
            known += [x for x in rep[kind] if x not in rest]
            rep["new_" + kind] = rest
        new = rep["new_lost"] + rep["new_changed"] + rep["new_added"]
        if new or not rep["title_edit_landed"]:
            bad += 1
            verdict = "NEW: %d diffs (lost %d, changed %d, added %d)%s" % (
                len(new), len(rep["new_lost"]), len(rep["new_changed"]), len(rep["new_added"]),
                "" if rep["title_edit_landed"] else ", EDIT MISSING")
        elif known:
            verdict = "known: %d expected diffs" % len(known)
        else:
            verdict = "ok"
        rows.append((stem, writer, ver, rt["out_version"], verdict))
    w = max(len(r[0]) for r in rows)
    for r in rows:
        print("%-*s  %-10s %-4s -> %-8s %s" % (w, r[0], r[1][:10], r[2], r[3], r[4]))
    clean = sum(1 for r in rows if r[4] == "ok")
    print("%d of %d files round-trip with nothing lost; %d with known findings; %d new" % (
        clean, len(rows), len(rows) - clean - bad, bad))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
