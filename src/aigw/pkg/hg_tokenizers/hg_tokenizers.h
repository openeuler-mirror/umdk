/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: c wrapper for HuggingFace tokenizers.
 * Create: 2025-06-18
 */

#ifndef HG_TOKENIZERS_H
#define HG_TOKENIZERS_H

#include <stdbool.h>
#include <stdint.h>

struct HgTokenIds {
    uint32_t *ids;
    uint32_t len;
};

void *hg_tokenizers_new_from_file(const char *filePath);
void hg_tokenizers_free(void *hg_tokenizer_handler);

struct HgTokenIds *hg_tokenizers_encode(void *hg_tokenizer_handler, const char *input, bool add_special_tokens);
void hg_tokenizers_free_token_ids(struct HgTokenIds *ids);

char *hg_tokenizers_decode(void *hg_tokenizer_handler, struct HgTokenIds *ids, bool skip_special_tokens);
void hg_tokenizers_free_string(char *input);

#endif
