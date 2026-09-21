#!/usr/bin/env sh
set -eu

PYTHON_BIN="${PYTHON_BIN:-python3}"
export ACSD_SKIP_NETWORK=1
export PYTHONDONTWRITEBYTECODE=1
"$PYTHON_BIN" check.py
