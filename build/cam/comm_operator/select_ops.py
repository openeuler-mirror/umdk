#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: resolve the final operator list to compile for a given SOC generation.
#              Reads operator_registry.json, validates user selection (-a list),
#              applies SHMEM availability and the fused_deep_moe base/w4a8 mutex rule,
#              then prints the selected operator directory names (one per line).
# Note:
#   - Operator identity = source directory name under ascend_kernels/.
#   - fused_deep_moe (base) and fused_deep_moe_w4a8 share identical source filenames
#     (fused_deep_moe.*), so they are mutually exclusive in one run package; --quant
#     selects the w4a8 variant. fused_deep_moe_fwk is independent (its files are
#     fused_deep_moe_fwk.*) and can coexist with either base or w4a8.
#   - "utils" is a shared header directory, always copied by the build script and
#     therefore never emitted here.

import argparse
import json
import os
import sys

FAMILY = "fused_deep_moe"
BASE = "fused_deep_moe"
W4A8 = "fused_deep_moe_w4a8"
FWK = "fused_deep_moe_fwk"


def die(msg):
    sys.stderr.write("ERROR: " + msg + "\n")
    sys.exit(1)


def load_registry(path):
    if not os.path.isfile(path):
        die(f"registry file not found: {path}")
    try:
        with open(path, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        die(f"registry JSON parse error: {path}: {e}")


def get_soc_list(registry, soc):
    soc_versions = registry.get("soc_versions", {})
    if soc not in soc_versions:
        supported = ", ".join(soc_versions.keys()) if soc_versions else "(none)"
        die(f"SOC '{soc}' not registered; supported: [{supported}]")
    return list(soc_versions[soc])


def get_meta(registry, op):
    return registry.get("operator_meta", {}).get(op, {})


def requires_shmem(registry, op):
    return bool(get_meta(registry, op).get("requires_shmem", False))


def split_ops(raw):
    """Split the -a list ('a;b;c') and validate no empty entries."""
    if raw is None:
        return None
    parts = [p.strip() for p in raw.split(";")]
    # Drop a single trailing empty that comes from a trailing ';' is NOT allowed:
    # empty entries indicate a typo like 'a;;b' or leading/trailing ';'.
    if any(p == "" for p in parts):
        die("-a list contains empty entry")
    return parts


def validate_user_ops(ops, soc_list):
    """Every -a entry must be in the SOC support list."""
    for op in ops:
        if op not in soc_list:
            die(f"operator '{op}' not in SOC support list; valid: [{', '.join(soc_list)}]")


def resolve(registry, soc_list, shmem, quant, user_ops):
    """Return the final ordered list of operator directory names to compile."""
    # 1. Determine the candidate set: full SOC list or explicit -a list.
    if user_ops is None:
        candidates = list(soc_list)
    else:
        candidates = list(user_ops)

    # 2. fused_deep_moe base/w4a8 mutex rules.
    #    base and w4a8 share identical op_host/op_kernel filenames (fused_deep_moe.*),
    #    so only one may be compiled into a single run package. fwk is a separate,
    #    independent operator (its files are fused_deep_moe_fwk.*) and is NOT part of
    #    this mutex -- it can always be compiled alongside either base or w4a8.
    #    --quant selects the w4a8 variant instead of base.
    has_base = BASE in candidates
    has_w4a8 = W4A8 in candidates

    if quant:
        # -q means the w4a8 variant is the representative. base is forbidden
        # (it would override w4a8's files). fwk is unaffected.
        if user_ops is not None and has_base:
            die(f"-q selects {W4A8}; remove {BASE} from -a or drop -q")
        # Full build under --quant: drop base, keep/ensure w4a8.
        candidates = [o for o in candidates if o != BASE]
        if W4A8 not in candidates:
            candidates.append(W4A8)
    else:
        # Without -q, base is the representative. If both base and w4a8 are
        # present they would collide on filenames.
        if has_base and has_w4a8:
            if user_ops is not None:
                die(f"{BASE} and {W4A8} share filenames; select only one, or use -q for {W4A8}")
            # Full build: keep base, drop w4a8 with a notice.
            sys.stderr.write(
                f"NOTE: dropping {W4A8} (shares filenames with {BASE} in the same run package)\n"
            )
            candidates = [o for o in candidates if o != W4A8]

    # 3. SHMEM filter: drop requires_shmem operators when SHMEM is not installed.
    if not shmem:
        dropped = [o for o in candidates if requires_shmem(registry, o)]
        for o in dropped:
            sys.stderr.write(f"NOTE: dropping {o} (requires SHMEM, which is not installed)\n")
        candidates = [o for o in candidates if not requires_shmem(registry, o)]

    # 4. Preserve registry order for determinism.
    ordered = [o for o in soc_list if o in candidates]
    return ordered


def main():
    parser = argparse.ArgumentParser(
        description="Resolve the CAM operator list to compile for a SOC generation."
    )
    parser.add_argument("--registry", required=True, help="path to operator_registry.json")
    parser.add_argument("--soc", required=True, help="target SOC generation, e.g. ascend910_93")
    parser.add_argument(
        "--shmem",
        choices=["1", "0"],
        required=True,
        help="whether SHMEM is installed (1/0)",
    )
    parser.add_argument(
        "--quant",
        action="store_true",
        help="select the fused_deep_moe_w4a8 variant instead of fused_deep_moe",
    )
    parser.add_argument(
        "--ops",
        default=None,
        help="semicolon-separated operator list (-a); omit to compile the full SOC set",
    )
    args = parser.parse_args()

    registry = load_registry(args.registry)
    soc_list = get_soc_list(registry, args.soc)
    user_ops = split_ops(args.ops)
    if user_ops is not None:
        validate_user_ops(user_ops, soc_list)

    final_ops = resolve(registry, soc_list, args.shmem == "1", args.quant, user_ops)

    if not final_ops:
        die("no operators to compile after filtering (check SHMEM installation or -a selection)")

    for op in final_ops:
        print(op)


if __name__ == "__main__":
    main()
