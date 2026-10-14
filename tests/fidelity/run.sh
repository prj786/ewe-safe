#!/usr/bin/env bash
# the phase-0 go/no-go gate: see run.py
exec python3 "$(dirname "$0")/run.py" "$@"
