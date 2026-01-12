/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: define the options of tokenizer
 * Create: 2025-06-14
 */

// Package tokenizers provides functions of tokenization for AIGW.
package tokenizers

// TokenizerOption is the option for tokenizer
type TokenizerOption func(t *Tokenizer) error
