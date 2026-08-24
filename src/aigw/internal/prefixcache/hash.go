/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Hash computation for prefix cache, matching vLLM/aibrix implementation.
 *   - Tokens are encoded as uint32 big-endian (4 bytes per token)
 *   - blockSize is the number of tokens per block (e.g., 16 tokens per block)
 *   - bytesPerBlock = blockSize * 4 (16 tokens * 4 bytes = 64 bytes per block)
 * Create: 2026-05-21
 * Updated: 2026-06-03
 */

package prefixcache

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"

	"github.com/OneOfOne/xxhash"
	"huawei.com/aigw/pkg/log"
)

const (
	// bytesPerToken is the number of bytes per token (uint32 big-endian)
	bytesPerToken = 4
)

type hasher struct {
	seed          uint64
	blockSize     int // Number of tokens per block
	bytesPerBlock int // Total bytes per block = blockSize * bytesPerToken
}

func newHasher(seed uint64, blockSize int) *hasher {
	return &hasher{
		seed:          seed,
		blockSize:     blockSize,
		bytesPerBlock: blockSize * bytesPerToken,
	}
}

// computeHash computes the hash for a single block.
// blockTokens should be exactly bytesPerBlock bytes (blockSize tokens * 4 bytes each).
func (h *hasher) computeHash(parentHash uint64, blockTokens []byte) uint64 {
	digest := xxhash.NewS64(h.seed)
	var parentHashBytes [8]byte
	// Use big-endian for parent hash (matching aibrix)
	binary.BigEndian.PutUint64(parentHashBytes[:], parentHash)
	digest.Write(parentHashBytes[:])
	digest.Write(blockTokens)
	return digest.Sum64()
}

// getPrefixHashes computes prefix hashes for given token bytes.
// Input tokens should be encoded as: blockSize tokens per block, each token as 4 bytes big-endian uint32.
// Returns hash for each complete block (partial blocks at end are ignored).
func (h *hasher) getPrefixHashes(tokens []byte) []uint64 {
	numBlocks := len(tokens) / h.bytesPerBlock
	if numBlocks == 0 {
		return nil
	}

	if log.DebugEnabled() {
		tokensHex := fmt.Sprintf("%x", tokens)
		maxHexLen := 64
		if len(tokensHex) < maxHexLen {
			maxHexLen = len(tokensHex)
		}
		log.Debug().Msgf("[hash] getPrefixHashes: seed=%d, blockSize=%d, bytesPerBlock=%d, numBlocks=%d, tokensLen=%d, tokensHex=%s",
			h.seed, h.blockSize, h.bytesPerBlock, numBlocks, len(tokens), tokensHex[:maxHexLen])
	}

	prefixHashes := make([]uint64, 0, numBlocks)
	parentHash := h.seed
	var parentHashBytes [8]byte

	for i := 0; i < len(tokens); i += h.bytesPerBlock {
		end := i + h.bytesPerBlock
		if end > len(tokens) {
			// Don't hash incomplete blocks
			break
		}

		digest := xxhash.NewS64(h.seed)
		// Use big-endian for parent hash (matching aibrix)
		binary.BigEndian.PutUint64(parentHashBytes[:], parentHash)
		digest.Write(parentHashBytes[:])
		digest.Write(tokens[i:end])

		currentHash := digest.Sum64()
		prefixHashes = append(prefixHashes, currentHash)

		// Debug logging for each block
		if log.DebugEnabled() {
			blockTokens := tokens[i:end]
			log.Debug().Msgf("[hash] block %d: parentHash=%d, blockTokensHex=%s, xxhash=%d",
				len(prefixHashes)-1, parentHash, fmt.Sprintf("%x", blockTokens), currentHash)
		}

		parentHash = currentHash
	}

	return prefixHashes
}

// TokenIDsToBytes converts []int64 token IDs to []byte.
// Each token is encoded as uint32 big-endian (4 bytes).
// If a token exceeds uint32 max, it will be truncated.
func TokenIDsToBytes(tokenIDs []int64) []byte {
	if len(tokenIDs) == 0 {
		return nil
	}
	tokens := make([]byte, len(tokenIDs)*bytesPerToken)
	for i, id := range tokenIDs {
		// Truncate to uint32 and use big-endian
		binary.BigEndian.PutUint32(tokens[i*bytesPerToken:], uint32(id))
	}
	return tokens
}

func generateSeed() uint64 {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return r.Uint64()
}
