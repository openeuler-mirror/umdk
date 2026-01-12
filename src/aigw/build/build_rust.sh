#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# building rust components

set -e

function build_hg_tokenizers() {
  echo "building hg tokenizers"
  mkdir -p "${ROOT_DIR}/output/hg_tokenizers"

  cd "${ROOT_DIR}"

  export RUSTFLAGS="-C link-arg=-Wl,-Bsymbolic -C link-arg=-rdynamic -C link-arg=-Wl,--no-undefined"

  if [[ "$WITH_DEBUG" == "ON" ]];then
    cargo build -v --target-dir "${ROOT_DIR}/output/hg_tokenizers"
  else
    cargo build -v --release --target-dir "${ROOT_DIR}/output/hg_tokenizers"
  fi
  echo "finished to build hg tokenizers"
}

function build_rust_components() {
  build_hg_tokenizers
}
