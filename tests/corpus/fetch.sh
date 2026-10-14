#!/usr/bin/env bash
# Download the fidelity corpus (corpus.json) into tests/corpus/files/ at
# pinned commits, then build the synthetic stress file. Third-party test
# data stays out of the repo: files/ and .src/ are gitignored.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
src="$here/.src"
files="$here/files"
mkdir -p "$src" "$files"

python3 - "$here/corpus.json" <<'PY' | while read -r name repo commit dir; do
import json, sys
c = json.load(open(sys.argv[1]))
for name, s in c["sources"].items():
    print(name, s["repo"], s["commit"], s["dir"])
PY
    if [ ! -d "$src/$name/.git" ]; then
        git init -q "$src/$name"
        git -C "$src/$name" remote add origin "$repo"
    fi
    git -C "$src/$name" sparse-checkout set "$dir" >/dev/null 2>&1 || true
    git -C "$src/$name" fetch -q --depth 1 --filter=blob:none origin "$commit"
    git -C "$src/$name" -c advice.detachedHead=false checkout -q FETCH_HEAD
    mkdir -p "$files/$name"
    cp -f "$src/$name/$dir"/*.kdbx "$files/$name/" 2>/dev/null || true
    cp -f "$src/$name/$dir"/*.key "$src/$name/$dir"/*.keyx "$files/$name/" 2>/dev/null || true
done

mkdir -p "$files/synthetic"
base="$files/keepass-rs/test_db_kdbx41_features.kdbx"
python3 "$here/../fidelity/make_synthetic.py" "$base" demopass "$files/synthetic/synth_rich.kdbx" >/dev/null
for where in meta group entry root attr interleaved; do
    python3 "$here/../fidelity/make_synthetic.py" "$base" demopass \
        "$files/synthetic/synth_unknown_$where.kdbx" "$where" >/dev/null
done
echo "corpus ready in $files"
