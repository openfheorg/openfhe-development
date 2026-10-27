#!/usr/bin/env python3
"""Regenerate all Phase-0 golden JSON under reference/golden/. Deterministic:
sorted keys, fixed precision -> a clean `git diff` unless the math changed.

  python3 tools/gen_golden.py            # write golden/*.json
  python3 tools/gen_golden.py --check    # recompute in-memory, diff vs disk (no writes)
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ci_ckks.golden import build_all  # noqa: E402

GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "..", "golden")


def _dump(obj):
    return json.dumps(obj, indent=2, sort_keys=True)


def main():
    check = "--check" in sys.argv
    os.makedirs(GOLDEN_DIR, exist_ok=True)
    artifacts = build_all()
    failures = []
    for name, obj in artifacts.items():
        path = os.path.join(GOLDEN_DIR, name)
        text = _dump(obj)
        if check:
            if not os.path.exists(path):
                failures.append("MISSING: %s" % name)
                continue
            with open(path) as f:
                on_disk = f.read()
            if on_disk.strip() != text.strip():
                failures.append("DRIFT: %s" % name)
        else:
            with open(path, "w") as f:
                f.write(text + "\n")
            print("wrote", name)
    if check:
        if failures:
            print("GOLDEN CHECK FAILED:")
            for f in failures:
                print("  ", f)
            sys.exit(1)
        print("golden check: OK (%d artifacts)" % len(artifacts))


if __name__ == "__main__":
    main()
