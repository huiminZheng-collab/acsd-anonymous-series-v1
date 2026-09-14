"""Seeded generative differential test for the restricted JSON profile."""
from __future__ import annotations

import json
import argparse
import random
import statistics
import string

from canonical_diff_runner import node_side, py_side


SEED = 20260912
SAMPLES = 1000
VALUES = [None, True, False, 0, 1, -1, 9007199254740991, -9007199254740991,
          "", "anonymous", "匿名", "e\u0301", "😀", "line\nbreak"]


def generated(rng: random.Random, depth: int = 0):
    if depth >= 4 or rng.random() < 0.42:
        return rng.choice(VALUES)
    if rng.random() < 0.45:
        return [generated(rng, depth + 1) for _ in range(rng.randrange(5))]
    result = {}
    for _ in range(rng.randrange(5)):
        key = "".join(rng.choice(string.ascii_letters + string.digits + "_-")
                      for _ in range(rng.randrange(1, 9)))
        result[key] = generated(rng, depth + 1)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    args = parser.parse_args()
    rng = random.Random(SEED)
    texts = []
    for index in range(SAMPLES):
        obj = generated(rng)
        canonical_text = json.dumps(
            obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        )
        if index % 3 == 0:
            text = canonical_text
        elif index % 3 == 1:
            text = " " + canonical_text
        else:
            text = json.dumps(obj, ensure_ascii=False, sort_keys=False, separators=(",", ":"))
        texts.append(text)

    py_results = [py_side(text) for text in texts]
    node_results = node_side(texts)
    byte_agreements = 0
    verdict_agreements = 0
    failures = []
    for index, (py_result, node_result) in enumerate(zip(py_results, node_results)):
        same_bytes = (py_result.get("ok") and node_result.get("ok")
                      and py_result.get("hex") == node_result.get("hex"))
        same_verdict = py_result.get("is_canonical") == node_result.get("is_canonical")
        byte_agreements += int(same_bytes)
        verdict_agreements += int(same_verdict)
        if not (same_bytes and same_verdict):
            failures.append(index)

    report = {
        "seed": SEED,
        "samples": SAMPLES,
        "byte_agreements": byte_agreements,
        "text_verdict_agreements": verdict_agreements,
        "failure_indices": failures,
    }
    if args.output:
        __import__("pathlib").Path(args.output).write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )
    print(json.dumps(report))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
