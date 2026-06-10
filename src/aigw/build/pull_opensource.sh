#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

set -e

function down_one()
{
  if [ ! -d "$3" ];then
      git clone --depth=1 -b $1 $2 $3
  fi

  if [ ! -d "$3" ];then
      echo "download $2 failed!"
      return 1
  fi
  echo "download $2 success!"
}

# Patch LightGBM's arrow.h so the cgo C-mode preamble (pkg/lightgbm/lightgbm.go
# includes <LightGBM/c_api.h>) compiles. Upstream arrow.h pulls in C++ stdlib
# headers and a `namespace LightGBM { ... }` block unconditionally, and uses
# `ArrowSchema*`/`ArrowArray*` (struct-tag-less) typedefs that are valid only
# in C++. We guard the C++-only sections with `#ifdef __cplusplus` and add
# C-side typedefs.
function patch_lightgbm_headers()
{
  local f="$ROOT_DIR/open_source/LightGBM-v4.6.0/include/LightGBM/arrow.h"
  if [ ! -f "$f" ] || grep -q "AIGW_PATCHED" "$f"; then
    return 0
  fi
  python3 - "$f" <<'PY'
import sys
p = open(sys.argv[1]).read()
inc_old = ("#define LIGHTGBM_ARROW_H_\n\n"
           "#include <algorithm>\n#include <cstdint>\n#include <functional>\n"
           "#include <iterator>\n#include <limits>\n#include <memory>\n"
           "#include <utility>\n#include <vector>\n#include <stdexcept>\n")
inc_new = ("#define LIGHTGBM_ARROW_H_\n// AIGW_PATCHED\n\n"
           "#ifdef __cplusplus\n"
           "#include <algorithm>\n#include <cstdint>\n#include <functional>\n"
           "#include <iterator>\n#include <limits>\n#include <memory>\n"
           "#include <utility>\n#include <vector>\n#include <stdexcept>\n"
           "#endif\n")
assert inc_old in p, "include block not found"
p = p.replace(inc_old, inc_new, 1)

old_close = "#ifdef __cplusplus\n}\n#endif\n\n/* ----"
new_close = ("\ntypedef struct ArrowSchema ArrowSchema;\n"
             "typedef struct ArrowArray ArrowArray;\n\n"
             "#ifdef __cplusplus\n}\n#endif\n\n/* ----")
assert old_close in p, "close of extern C block not found"
p = p.replace(old_close, new_close, 1)

p = p.replace("namespace LightGBM {",
              "#ifdef __cplusplus\nnamespace LightGBM {", 1)
p = p.replace("}  // namespace LightGBM",
              "}  // namespace LightGBM\n#endif  // __cplusplus", 1)
p = p.replace('#include "arrow.tpp"',
              '#ifdef __cplusplus\n#include "arrow.tpp"\n#endif', 1)
open(sys.argv[1], "w").write(p)
PY
  echo "patched arrow.h for cgo C-mode compilation"
}

function pull_opensource()
{
  echo "downloading package from public mirrors"
  mkdir -p $ROOT_DIR/open_source
  cd $ROOT_DIR/open_source
  down_one v4.6.0             https://github.com/microsoft/LightGBM.git           LightGBM-v4.6.0
  down_one 3.4.0              https://gitlab.com/libeigen/eigen.git               eigen-3.4.0
  down_one v0.8.0             https://github.com/lemire/fast_double_parser.git    fast_double_parser-v0.8.0
  down_one boost-1.87.0.beta1 https://github.com/boostorg/compute.git             compute-1.87.0.beta1
  down_one 11.1.2             https://github.com/fmtlib/fmt.git                   fmt-11.1.2
  cd $ROOT_DIR
  rm -rf open_source/LightGBM-v4.6.0/external_libs/eigen
  ln -s $ROOT_DIR/open_source/eigen-3.4.0/ $ROOT_DIR/open_source/LightGBM-v4.6.0/external_libs/eigen
  rm -rf open_source/LightGBM-v4.6.0/external_libs/compute
  ln -s $ROOT_DIR/open_source/compute-1.87.0.beta1/ $ROOT_DIR/open_source/LightGBM-v4.6.0/external_libs/compute
  rm -rf open_source/LightGBM-v4.6.0/external_libs/fast_double_parser
  ln -s $ROOT_DIR/open_source/fast_double_parser-v0.8.0/ $ROOT_DIR/open_source/LightGBM-v4.6.0/external_libs/fast_double_parser
  rm -rf open_source/LightGBM-v4.6.0/external_libs/fmt
  ln -s $ROOT_DIR/open_source/fmt-11.1.2/ $ROOT_DIR/open_source/LightGBM-v4.6.0/external_libs/fmt

  patch_lightgbm_headers
}
