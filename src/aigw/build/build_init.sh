#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# define public variables

set -e

function set_env () {
  export GO111MODULE=on
  export GOPROXY=https://cmc.centralrepo.rnd.huawei.com/artifactory/go-central-repo/
  export GONOSUMDB=*
}

function init_cgo_flag () {
  LIGHTGBM_ROOT_DIR=$ROOT_DIR/open_source/LightGBM-v4.6.0
  LIGHTGBM_HEADER_DIR="$LIGHTGBM_ROOT_DIR/include/"
  HG_TOKENIZERS_HEADER_DIR="$ROOT_DIR/pkg/hg_tokenizers/"
  AIGW_CFLAGS_COMMON="-Wall -Werror -rdynamic -fno-strict-aliasing -fstack-protector-strong -fPIC -Wl,--build-id=none"
  AIGW_CFLAGS_DIRS="-I$LIGHTGBM_HEADER_DIR -I$HG_TOKENIZERS_HEADER_DIR"

  if [[ "${WITH_DEBUG}" == "ON" ]];then
    HG_TOKENIZERS_LD_DIR="${ROOT_DIR}/output/hg_tokenizers/debug"
    AIGW_CFLAGS="$AIGW_CFLAGS_COMMON $AIGW_CFLAGS_DIRS -O0"
  else
    HG_TOKENIZERS_LD_DIR="${ROOT_DIR}/output/hg_tokenizers/release"
    AIGW_CFLAGS="$AIGW_CFLAGS_COMMON $AIGW_CFLAGS_DIRS -D_FORTIFY_SOURCE=2 -O2"
  fi

  export CGO_ENABLED=1
  export CGO_CFLAGS="$AIGW_CFLAGS"
  export CGO_LDFLAGS="-fPIE -Wl,-z,relro,-z,now -Wl,-z,noexecstack -lstdc++ -L$LIGHTGBM_ROOT_DIR -L${HG_TOKENIZERS_LD_DIR}"
}

function init () {
  ROOT_DIR="$PWD"
  set_env
  init_cgo_flag
}