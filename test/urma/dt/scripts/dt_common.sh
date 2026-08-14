#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
#

# Fail loudly when any stage of a fingerprint pipeline fails (e.g. missing
# temp file, unreadable source path). Without this, a failed pipeline would
# hash empty input and could be cached as a valid fingerprint.
set -o pipefail

dt_source_fingerprint()
{
    local tmp
    local hash
    local p
    tmp=$(mktemp "${TMPDIR:-/tmp}/dt_fp.XXXXXX") || return 1
    for p in "$@"; do
        if [ -f "$p" ]; then
            if ! sha256sum "$p" >>"$tmp" 2>/dev/null; then
                rm -f "$tmp"
                return 1
            fi
        elif [ -d "$p" ]; then
            if ! find "$p" -type f \
                ! -path '*/build*/*' \
                ! -path '*/CMakeFiles/*' \
                ! -name '*.o' \
                ! -name '*.a' \
                ! -name '*.so' \
                ! -name '*.so.*' \
                -print0 2>/dev/null |
                sort -z |
                xargs -0 -r sha256sum >>"$tmp" 2>/dev/null; then
                rm -f "$tmp"
                return 1
            fi
        fi
    done
    if [ ! -s "$tmp" ]; then
        rm -f "$tmp"
        return 1
    fi
    hash=$(sort "$tmp" 2>/dev/null | sha256sum | awk '{print $1}') || {
        rm -f "$tmp"
        return 1
    }
    rm -f "$tmp"
    printf '%s\n' "$hash"
}

dt_fingerprint_save()
{
    local file=$1
    local hash=$2
    mkdir -p "$(dirname "$file")"
    printf '%s\n' "$hash" >"$file"
}

dt_fingerprint_matches()
{
    local file=$1
    local hash=$2
    local stored=""
    if [ ! -f "$file" ]; then
        return 1
    fi
    read -r stored <"$file" || return 1
    [ "$stored" = "$hash" ]
}
