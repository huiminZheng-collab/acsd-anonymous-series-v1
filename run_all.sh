#!/usr/bin/env sh
set -eu

PYTHON_BIN="${PYTHON_BIN:-python3}"
export ACSD_SKIP_NETWORK=1

"$PYTHON_BIN" -m unittest -q
"$PYTHON_BIN" design/canonical_diff_runner.py
"$PYTHON_BIN" design/canonical_fuzz_runner.py
"$PYTHON_BIN" design/benchmark_core.py
"$PYTHON_BIN" verify_v1_fixture.py
"$PYTHON_BIN" generate_demo.py
"$PYTHON_BIN" verify_pec.py

if command -v lake >/dev/null 2>&1; then
  (cd formal && lake build && lake env lean AxiomAudit.lean)
  printf '%s\n' '{"formal_status":"PASS","lean":"4.33.1"}'
else
  printf '%s\n' '{"formal_status":"PENDING_TOOLCHAIN","hint":"install elan/lake or run CI"}'
fi
