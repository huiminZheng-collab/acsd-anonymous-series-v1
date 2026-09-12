#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python_bin="${PYTHON_BIN:-python3}"
deps_dir="$project_dir/.deps"
vendor_dir="$project_dir/vendor"
if [[ ! -f "$deps_dir/cbor2/__init__.py" ]]; then
  PYTHONDONTWRITEBYTECODE=1 "$python_bin" -m pip install --target "$deps_dir" --require-hashes --no-index --find-links "$vendor_dir" -r "$project_dir/requirements.lock"
fi
PYTHONPATH="$deps_dir${PYTHONPATH:+:$PYTHONPATH}" PYTHONDONTWRITEBYTECODE=1 "$python_bin" "$project_dir/generate.py"
node "$project_dir/verify-standalone.cjs" artifacts/standalone-packages/p-v1.json
node "$project_dir/verify-independent.cjs"
node "$project_dir/build-manifest.cjs"
node "$project_dir/verify-manifest.cjs"
