/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 *
 * ubs-hcom is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *      http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

/* Pure parsing helpers shared by core.cpp (init/alloc args) and main.cpp
 * (script tokenization). No access to umq static state — safe to compile
 * as its own TU without including umq_qbuf_pool.c. */

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "qbuf_pool_tool.h"

uint64_t ParseSize(const char *s)
{
    if (s == nullptr || s[0] == '\0') {
        return 0;
    }
    char *end = nullptr;
    uint64_t v = strtoull(s, &end, 10);
    if (end == s) {
        return 0;
    }
    if (end != nullptr && end[0] != '\0') {
        char c = (char)tolower((unsigned char)end[0]);
        if (c == 'k') {
            v *= 1024;
        } else if (c == 'm') {
            v *= 1024 * 1024;
        } else if (c == 'g') {
            v *= 1024 * 1024 * 1024;
        }
    }
    return v;
}

umq_buf_block_size_t BaseStrToEnum(const char *s)
{
    if (s == nullptr) {
        return BLOCK_SIZE_4K;
    }
    std::string str(s);
    if (str == "4K" || str == "4k") {
        return BLOCK_SIZE_4K;
    }
    if (str == "8K" || str == "8k") {
        return BLOCK_SIZE_8K;
    }
    if (str == "16K" || str == "16k") {
        return BLOCK_SIZE_16K;
    }
    if (str == "32K" || str == "32k") {
        return BLOCK_SIZE_32K;
    }
    if (str == "64K" || str == "64k") {
        return BLOCK_SIZE_64K;
    }
    if (str == "128K" || str == "128k") {
        return BLOCK_SIZE_128K;
    }
    if (str == "256K" || str == "256k") {
        return BLOCK_SIZE_256K;
    }
    if (str == "512K" || str == "512k") {
        return BLOCK_SIZE_512K;
    }
    if (str == "1M" || str == "1m") {
        return BLOCK_SIZE_1M;
    }
    return BLOCK_SIZE_4K;
}

/* Reverse map: byte count → umq_buf_block_size_t enum. Mirrors the forward
 * mapping in UmqSetting::BlockSizeToBytes (umq_setting.cpp:314-338). Used by
 * DoInit to derive base from blockSizes[0] automatically — eliminates the
 * redundant `base=` init param (base must equal explicit_block_sizes[0]
 * per umq_qbuf_pool.c:1529 validation). Default fallback BLOCK_SIZE_4K
 * for invalid sizes; production init will reject via :1519 check. */
umq_buf_block_size_t BlkSizeToEnum(uint32_t bytes)
{
    switch (bytes) {
        case 4096:    return BLOCK_SIZE_4K;
        case 8192:    return BLOCK_SIZE_8K;
        case 16384:   return BLOCK_SIZE_16K;
        case 32768:   return BLOCK_SIZE_32K;
        case 65536:   return BLOCK_SIZE_64K;
        case 131072:  return BLOCK_SIZE_128K;
        case 262144:  return BLOCK_SIZE_256K;
        case 524288:  return BLOCK_SIZE_512K;
        case 1048576: return BLOCK_SIZE_1M;
        default:      return BLOCK_SIZE_4K;
    }
}

umq_buf_mode_t ModeStrToEnum(const char *s)
{
    if (s == nullptr) {
        return UMQ_BUF_SPLIT;
    }
    std::string str(s);
    if (str == "combine" || str == "COMBINE") {
        return UMQ_BUF_COMBINE;
    }
    return UMQ_BUF_SPLIT;
}

bool OnOffToBool(const char *s, bool def)
{
    if (s == nullptr) {
        return def;
    }
    std::string str(s);
    if (str == "on" || str == "ON" || str == "true" || str == "1") {
        return true;
    }
    if (str == "off" || str == "OFF" || str == "false" || str == "0") {
        return false;
    }
    return def;
}

bool SplitKv(const std::string &tok, std::string &k, std::string &v)
{
    size_t pos = tok.find('=');
    if (pos == std::string::npos) {
        return false;
    }
    k = tok.substr(0, pos);
    v = tok.substr(pos + 1);
    return true;
}

std::vector<std::string> Tokenize(const char *line)
{
    std::vector<std::string> toks;
    std::string cur;
    for (const char *p = line; *p; ++p) {
        if (*p == '#') {
            break; /* inline comment — rest of line ignored */
        }
        if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
            if (!cur.empty()) {
                toks.push_back(cur);
                cur.clear();
            }
        } else {
            cur.push_back(*p);
        }
    }
    if (!cur.empty()) {
        toks.push_back(cur);
    }
    return toks;
}
