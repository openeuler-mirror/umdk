#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Check API-case coverage for URMA fuzz entry files."""

import argparse
import json
import re
from pathlib import Path


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*", "", text)
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def parse_api_names(header):
    text = strip_comments(Path(header).read_text(encoding="utf-8"))
    pattern = re.compile(r"[A-Za-z_][\w\s\*\[\],]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*;", re.S)
    return [name for name in pattern.findall(text) if name not in {"if", "for", "while", "switch"}]


def parse_case_names(fuzz_file):
    text = Path(fuzz_file).read_text(encoding="utf-8")
    pattern = re.compile(r'\{\s*"([A-Za-z_]\w*)"\s*,\s*Fuzz_[A-Za-z_]\w*\s*\}')
    return pattern.findall(text)


def calc_one(name, header, fuzz_file):
    api_names = parse_api_names(header)
    case_names = parse_case_names(fuzz_file)
    case_set = set(case_names)
    missing = [api for api in api_names if api not in case_set]
    extra = [case for case in case_names if case not in set(api_names)]
    covered = len(api_names) - len(missing)
    rate = 100.0 if not api_names else covered * 100.0 / len(api_names)
    return {
        "name": name,
        "header": str(header),
        "fuzz_file": str(fuzz_file),
        "api_count": len(api_names),
        "case_count": len(case_names),
        "covered": covered,
        "coverage": rate,
        "missing": missing,
        "extra": extra,
    }


def write_report(report_path, results):
    total_api = sum(item["api_count"] for item in results)
    total_covered = sum(item["covered"] for item in results)
    total_rate = 100.0 if total_api == 0 else total_covered * 100.0 / total_api

    lines = ["===== phase_fuzz API case coverage summary ====="]
    for item in results:
        lines.append(
            f"{item['name']}: {item['covered']}/{item['api_count']} APIs covered "
            f"({item['coverage']:.1f}%), cases={item['case_count']}"
        )
        if item["missing"]:
            lines.append(f"{item['name']} missing: {', '.join(item['missing'])}")
        if item["extra"]:
            lines.append(f"{item['name']} extra cases: {', '.join(item['extra'])}")
    lines.append(f"total: {total_covered}/{total_api} APIs covered ({total_rate:.1f}%)")

    report = Path(report_path)
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report.with_suffix(".json").write_text(
        json.dumps({"total_api": total_api, "total_covered": total_covered,
                    "coverage": total_rate, "results": results}, indent=2),
        encoding="utf-8")
    print("\n".join(lines))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--urma-header", required=True)
    parser.add_argument("--uvs-header", required=True)
    parser.add_argument("--urma-fuzz", required=True)
    parser.add_argument("--uvs-fuzz", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()

    results = [
        calc_one("liburma", args.urma_header, args.urma_fuzz),
        calc_one("libuvs", args.uvs_header, args.uvs_fuzz),
    ]
    write_report(args.report, results)

    for item in results:
        if item["missing"] or item["extra"]:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
