"""Small reproducible scaling experiment for canonical hash/manifest checks."""
from __future__ import annotations

import hashlib
import argparse
import json
import statistics
import time
import tracemalloc
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from canonical_json import canonical  # noqa: E402


SIZES = (10, 100, 1000, 5000)
REPETITIONS = 5


def release(index: int):
    return {
        "authors": [{"key_id": f"key-{index % 7}", "slot": 1}],
        "content": {"path": f"paper/{index}", "sha256": f"{index:064x}"[-64:]},
        "slot": {"line": "main", "version": index + 1, "work_id": f"urn:uuid:synthetic-{index}"},
    }


def exercise(size: int):
    objects = [release(i) for i in range(size)]
    payloads = [canonical(obj) for obj in objects]
    manifest = [hashlib.sha256(payload).digest() for payload in payloads]
    if not all(hashlib.sha256(payload).digest() == expected
               for payload, expected in zip(payloads, manifest)):
        raise AssertionError("manifest verification failed")
    ranks = list(range(size, 0, -1))
    if not all(ranks[i] > ranks[i + 1] for i in range(len(ranks) - 1)):
        raise AssertionError("rank certificate failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        help="optional path for deliberately refreshing a frozen benchmark report",
    )
    args = parser.parse_args()
    rows = []
    for size in SIZES:
        timings = []
        peaks = []
        for _ in range(REPETITIONS):
            tracemalloc.start()
            started = time.perf_counter()
            exercise(size)
            timings.append((time.perf_counter() - started) * 1000)
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            peaks.append(peak / (1024 * 1024))
        rows.append({
            "objects": size,
            "median_ms": round(statistics.median(timings), 3),
            "min_ms": round(min(timings), 3),
            "peak_mib": round(max(peaks), 3),
        })
    report = {
        "scope": "in-memory canonicalize+sha256 manifest verification+linear rank scan",
        "repetitions": REPETITIONS,
        "results": rows,
    }
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
