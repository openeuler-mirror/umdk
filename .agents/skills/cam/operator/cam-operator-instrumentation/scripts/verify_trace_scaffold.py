#!/usr/bin/env python3
"""
Verify trace scaffold files and compile hook integration.
"""

from __future__ import annotations

import argparse
from pathlib import Path


REQUIRED_FILES = (
    "trace_preprocessor.py",
    "trace_utils.py",
    "trace_save.py",
    "trace_collector.py",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify generated trace scaffold and compile hook.")
    parser.add_argument("--build-dir", required=True, help="build module directory containing trace_*.py")
    parser.add_argument("--compile-script", required=False, help="compile script to verify hook insertion")
    args = parser.parse_args()

    base = Path(args.build_dir)
    missing = []
    for f in REQUIRED_FILES:
        p = base / f
        if not p.exists():
            missing.append(str(p))

    if missing:
        print("missing files:")
        for m in missing:
            print(f"  - {m}")
    else:
        print("trace scaffold files: OK")

    if args.compile_script:
        text = Path(args.compile_script).read_text(encoding="utf-8")
        has_start = "# TRACE_PREPROCESSOR_HOOK_START" in text
        has_end = "# TRACE_PREPROCESSOR_HOOK_END" in text
        if has_start and has_end:
            print("compile hook: OK")
        else:
            print("compile hook: MISSING")

    if missing:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
