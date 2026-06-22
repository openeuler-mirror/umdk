/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: define the functions of sentencepiece tokenizer.
 * Create: 2025-06-14
 */

// Package tokenizers provides functions of tokenization for AIGW.
package tokenizers

/*
#cgo LDFLAGS: -lhuawei_aigw_tokenizers -ldl -lm -lstdc++
#include <stdlib.h>
#include <stdbool.h>
#include "hg_tokenizers.h"

typedef struct HgTokenIds HgTokenIds_t;
*/
import "C"
import (
	"fmt"
	"unsafe"

	"huawei.com/aigw/pkg/log"
)

type huggingFaceTokenizer struct {
	base               Tokenizer
	hgTokenizerHandler unsafe.Pointer
}

func newHuggingFaceTokenizer(opts ...TokenizerOption) *huggingFaceTokenizer {
	return &huggingFaceTokenizer{}
}

// InitFromFile will initialize the huggingFace tokenizer from file
func (h *huggingFaceTokenizer) InitFromFile(filePath string) error {
	log.Info().Msgf("init huggingFaceTokenizer from file %s", filePath)
	cPath := C.CString(filePath)
	defer C.free(unsafe.Pointer(cPath))

	handler := C.hg_tokenizers_new_from_file(cPath)
	if handler == nil {
		return fmt.Errorf("failed to load huggingFaceTokenizer from file %s", filePath)
	}
	h.hgTokenizerHandler = handler
	return nil
}

// Uninit huggingFace the tokenizer
func (h *huggingFaceTokenizer) Uninit() {
	if h.hgTokenizerHandler != nil {
		C.hg_tokenizers_free(h.hgTokenizerHandler)
		h.hgTokenizerHandler = nil
	}
	log.Info().Msgf("huggingFaceTokenizer uninitialized")
}

// Encode input string to token ids using huggingFace tokenizers
func (h *huggingFaceTokenizer) Encode(input string) ([]uint32, error) {
	log.Debug().Msgf("Encode by huggingFaceTokenizer")

	if len(input) == 0 {
		return []uint32{}, fmt.Errorf("input is empty")
	}

	cStr := C.CString(input)
	defer C.free(unsafe.Pointer(cStr))

	result := C.hg_tokenizers_encode(h.hgTokenizerHandler, cStr, C.bool(false))
	if result == nil {
		return nil, fmt.Errorf("failed to Encode huggingFaceTokenizer")
	}
	defer C.hg_tokenizers_free_token_ids(result) // Ensure release

	length := int(result.len)
	if length <= 0 {
		return []uint32{}, fmt.Errorf("failed to Encode by huggingFaceTokenizer, Encode length is zero")
	}

	slice := unsafe.Slice((*C.uint32_t)(result.ids), length)
	ids := make([]uint32, length)
	for i, v := range slice {
		ids[i] = uint32(v)
	}

	return ids, nil
}

// Decode the tokenIds to string using huggingFace tokenizers
func (h *huggingFaceTokenizer) Decode(tokenIds []uint32) (string, error) {
	log.Debug().Msgf("Decode by huggingFaceTokenizer")

	if len(tokenIds) == 0 {
		return "", fmt.Errorf("tokenIds is empty")
	}

	ids := C.malloc(C.size_t(len(tokenIds)) * C.sizeof_uint32_t)
	if ids == nil {
		return "", fmt.Errorf("failed to allocate ids")
	}
	defer C.free(unsafe.Pointer(ids))

	for i, id := range tokenIds {
		*((*C.uint32_t)(unsafe.Pointer(uintptr(ids) + uintptr(i)*C.sizeof_uint32_t))) = C.uint(id)
	}

	input := &C.HgTokenIds_t{
		ids: (*C.uint32_t)(ids),
		len: C.uint32_t(len(tokenIds)),
	}

	res := C.hg_tokenizers_decode(h.hgTokenizerHandler, input, C.bool(false))
	if res == nil {
		return "", fmt.Errorf("failed to Decode by huggingFaceTokenizer")
	}

	defer C.hg_tokenizers_free_string(res)

	return C.GoString(res), nil
}
