#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.

"""Check line coverage for newly added URMA source lines."""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


DEFAULT_SCOPE = (
    "src/urma/common",
    "src/urma/lib/urma/core",
    "src/urma/lib/urma/bond",
    "src/urma/lib/uvs",
)


def run_git(repo_root, args):
    return subprocess.check_output(["git", "-C", str(repo_root), *args], text=True)


def get_repo_root():
    return Path(run_git(Path.cwd(), ["rev-parse", "--show-toplevel"]).strip())


def get_default_base(repo_root):
    env_base = os.environ.get("URMA_UT_DIFF_BASE")
    if env_base:
        return env_base

    return run_git(repo_root, ["merge-base", "HEAD", "origin/master"]).strip()


def normalize_source_path(repo_root, source_path):
    path = Path(source_path)
    if path.is_absolute():
        try:
            return path.resolve().relative_to(repo_root).as_posix()
        except ValueError:
            return path.as_posix()
    return path.as_posix()


def parse_lcov(repo_root, coverage_file):
    coverage = {}
    current_file = None

    with coverage_file.open("r", encoding="utf-8") as lcov_file:
        for line in lcov_file:
            line = line.rstrip("\n")
            if line.startswith("SF:"):
                current_file = normalize_source_path(repo_root, line[3:])
                coverage.setdefault(current_file, {})
                continue

            if current_file is None or not line.startswith("DA:"):
                continue

            fields = line[3:].split(",", 2)
            if len(fields) < 2:
                continue
            coverage[current_file][int(fields[0])] = int(fields[1])

    return coverage


def parse_added_lines(diff_text):
    added_lines = {}
    current_file = None
    current_line = None
    hunk_re = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            path = line[4:]
            if path == "/dev/null":
                current_file = None
                continue
            current_file = path[2:] if path.startswith("b/") else path
            added_lines.setdefault(current_file, set())
            continue

        match = hunk_re.match(line)
        if match:
            current_line = int(match.group(1))
            continue

        if current_file is None or current_line is None:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            added_lines[current_file].add(current_line)
            current_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            continue
        else:
            current_line += 1

    return added_lines


def get_added_lines(repo_root, base, scope):
    diff_text = run_git(repo_root, ["diff", "--unified=0", f"{base}...HEAD", "--", *scope])
    return parse_added_lines(diff_text)


def check_diff_coverage(added_lines, coverage, threshold):
    instrumented = []
    uncovered = []

    for source_file in sorted(added_lines):
        file_coverage = coverage.get(source_file, {})
        for line_no in sorted(added_lines[source_file]):
            if line_no not in file_coverage:
                continue
            instrumented.append((source_file, line_no))
            if file_coverage[line_no] == 0:
                uncovered.append((source_file, line_no))

    if not instrumented:
        print("Diff coverage: no instrumented added lines")
        return 0

    covered = len(instrumented) - len(uncovered)
    rate = covered * 100.0 / len(instrumented)
    print(
        "Diff coverage: {:.1f}% ({}/{}) instrumented added lines covered".format(
            rate, covered, len(instrumented)
        )
    )

    if rate + 1e-9 >= threshold:
        return 0

    print("ERROR: diff coverage {:.1f}% is below required {:.1f}%".format(rate, threshold))
    for source_file, line_no in uncovered[:50]:
        print("UNCOVERED: {}:{}".format(source_file, line_no))
    if len(uncovered) > 50:
        print("UNCOVERED: ... {} more lines".format(len(uncovered) - 50))
    return 1


def main():
    parser = argparse.ArgumentParser(description="Check coverage for newly added URMA source lines.")
    parser.add_argument("--coverage", default="test/urma/reports/filtered.info")
    parser.add_argument("--base", default=None)
    parser.add_argument("--threshold", type=float, default=90.0)
    parser.add_argument("--scope", action="append", default=None)
    args = parser.parse_args()

    repo_root = get_repo_root()
    coverage_file = (repo_root / args.coverage).resolve()
    if not coverage_file.is_file():
        print("ERROR: coverage file not found: {}".format(coverage_file), file=sys.stderr)
        return 1

    base = args.base if args.base is not None else get_default_base(repo_root)
    scope = tuple(args.scope) if args.scope is not None else DEFAULT_SCOPE

    coverage = parse_lcov(repo_root, coverage_file)
    added_lines = get_added_lines(repo_root, base, scope)
    return check_diff_coverage(added_lines, coverage, args.threshold)


if __name__ == "__main__":
    sys.exit(main())
