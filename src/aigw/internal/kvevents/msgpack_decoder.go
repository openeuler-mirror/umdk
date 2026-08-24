/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: MessagePack decoder for vLLM KV Events, matching aibrix-main implementation.
 * Create: 2026-06-03
 * Reference: aibrix-main/pkg/cache/kvcache/msgpack_decoder.go
 */

package kvevents

import (
	"encoding/binary"
	"fmt"
	"math"

	msgpack "github.com/vmihailenco/msgpack/v5"
)

// DecodeEventBatch parses a raw msgpack batch of events.
// The batch contains [timestamp, [events...]] format from vLLM.
func DecodeEventBatch(data []byte, modelName string, instanceName string) (*EventBatch, error) {
	var rawBatch []interface{}
	if err := msgpack.Unmarshal(data, &rawBatch); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event batch: %w", err)
	}

	// If size of rawBatch is 3, the third element is the data parallel rank
	if len(rawBatch) == 3 {
		dataParallelRank, err := parseInt(rawBatch[2])
		if err != nil {
			return nil, fmt.Errorf("data_parallel_rank is not an int: %T", rawBatch[2])
		}
		_ = dataParallelRank // Not used in aigw currently
	} else if len(rawBatch) != 2 {
		return nil, fmt.Errorf("expected 2 elements in batch (ts, events), got %d", len(rawBatch))
	}

	// 0: batch timestamp
	tsFloat, ok := rawBatch[0].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid batch timestamp type: %T", rawBatch[0])
	}
	batchTS := int64(tsFloat * 1e9) // Convert to nanoseconds

	// 1: events array
	eventsRaw, ok := rawBatch[1].([]interface{})
	if !ok {
		return nil, fmt.Errorf("expected events array, got %T", rawBatch[1])
	}

	batch := &EventBatch{
		Timestamp: batchTS,
		Events:    make([]Event, 0, len(eventsRaw)),
	}

	for i, raw := range eventsRaw {
		arr, ok := raw.([]interface{})
		if !ok {
			return nil, fmt.Errorf("event %d: expected msgpack array, got %T", i, raw)
		}

		evt, err := parseEventArray(arr)
		if err != nil {
			return nil, fmt.Errorf("event %d: %w", i, err)
		}

		// Apply batch metadata
		applyBatchMetadata(evt, instanceName, modelName)
		batch.Events = append(batch.Events, evt)
	}

	return batch, nil
}

func parseEventArray(arr []interface{}) (Event, error) {
	if len(arr) == 0 {
		return nil, fmt.Errorf("empty event array")
	}

	// First element is event type tag
	rawTag, ok := arr[0].(string)
	if !ok {
		return nil, fmt.Errorf("event tag not string: %T", arr[0])
	}
	tag := EventType(rawTag)

	switch tag {
	case EventTypeBlockStored:
		// Minimum = 5 fields: [tag, block_hashes, parent_block_hash, token_ids, block_size]
		if len(arr) < 5 {
			return nil, fmt.Errorf("BlockStored requires at least 5 fields, got %d", len(arr))
		}

		// 1: block_hashes
		blockHashes, err := toBlockHashSlice(arr[1])
		if err != nil {
			return nil, fmt.Errorf("invalid block_hashes: %w", err)
		}

		// 2: parent_block_hash
		parentHash, err := toBlockHashPtr(arr[2])
		if err != nil {
			return nil, fmt.Errorf("invalid parent_block_hash: %w", err)
		}

		// 3: token_ids - decode as []uint32, then group by blockSize
		rawTokenIDs, ok := arr[3].([]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid token_ids type: %T", arr[3])
		}

		// 4: block_size (required)
		blockSize, err := parseInt(arr[4])
		if err != nil {
			return nil, fmt.Errorf("invalid block_size: %w", err)
		}

		// Decode tokenIDs as []uint32
		tokenIDs := make([]uint32, len(rawTokenIDs))
		for i, v := range rawTokenIDs {
			n, err := parseUint32(v)
			if err != nil {
				return nil, fmt.Errorf("token_ids[%d]: %w", i, err)
			}
			tokenIDs[i] = n
		}

		// Group tokens into blocks and convert to [][]byte (each block as bytes)
		tokenBytes, err := convertTokenIDsToBlocks(tokenIDs, blockSize)
		if err != nil {
			return nil, err
		}

		return &BlockStored{
			BlockHashes:     blockHashes,
			ParentBlockHash: parentHash,
			TokenIDs:        tokenBytes,
		}, nil

	case EventTypeBlockRemoved:
		if len(arr) < 2 {
			return nil, fmt.Errorf("BlockRemoved expects at least 2 fields, got %d", len(arr))
		}

		blockHashes, err := toBlockHashSlice(arr[1])
		if err != nil {
			return nil, fmt.Errorf("invalid block_hashes: %w", err)
		}

		return &BlockRemoved{
			BlockHashes: blockHashes,
		}, nil

	case EventTypeAllBlocksCleared:
		return &AllBlocksCleared{}, nil

	default:
		return nil, fmt.Errorf("unknown event type: %s", tag)
	}
}

func applyBatchMetadata(evt Event, instanceName string, modelName string) {
	switch e := evt.(type) {
	case *BlockStored:
		e.ModelName = modelName
		e.InstanceName = instanceName
	case *BlockRemoved:
		e.ModelName = modelName
		e.InstanceName = instanceName
	case *AllBlocksCleared:
		e.ModelName = modelName
		e.InstanceName = instanceName
	}
}

// toBlockHashSlice converts block_hashes field to []int64.
// Supports both legacy int64 format and new []byte format (SHA-256).
func toBlockHashSlice(v any) ([]int64, error) {
	raw, ok := v.([]interface{})
	if !ok {
		return nil, fmt.Errorf("expected []interface{}, got %T", v)
	}

	out := make([]int64, len(raw))
	for i, x := range raw {
		hash, err := parseBlockHashToInt64(x)
		if err != nil {
			return nil, fmt.Errorf("block_hashes[%d]: %w", i, err)
		}
		out[i] = hash
	}
	return out, nil
}

// toInt64 converts any numeric type or byte slice to int64.
// Returns (value, ok). Used as the common converter for all numeric parse functions.
func toInt64(v any) (int64, bool) {
	switch x := v.(type) {
	case []byte:
		return bytesToInt64(x), true
	case string:
		return bytesToInt64([]byte(x)), true
	case int:
		return int64(x), true
	case int8:
		return int64(x), true
	case int16:
		return int64(x), true
	case int32:
		return int64(x), true
	case int64:
		return x, true
	case uint:
		return int64(x), true
	case uint8:
		return int64(x), true
	case uint16:
		return int64(x), true
	case uint32:
		return int64(x), true
	case uint64:
		return int64(x), true
	case float64:
		return int64(x), true
	default:
		return 0, false
	}
}

// bytesToInt64 converts a byte array to int64 using big-endian encoding.
func bytesToInt64(b []byte) int64 {
	if len(b) >= 8 {
		return int64(binary.BigEndian.Uint64(b[:8]))
	}
	// Pad with leading zeros for big-endian
	padded := make([]byte, 8)
	copy(padded[8-len(b):], b)
	return int64(binary.BigEndian.Uint64(padded))
}

// parseBlockHashToInt64 parses a single block hash and converts it to int64.
// Supports:
// 1. int64 types (legacy format from old vLLM)
// 2. []byte (new format from vLLM v1 - SHA-256, uses first 8 bytes)
// 3. Various numeric and string types
func parseBlockHashToInt64(v any) (int64, error) {
	x, ok := toInt64(v)
	if !ok {
		return 0, fmt.Errorf("unsupported block hash type: %T", v)
	}
	// float64 needs range and fractional check for block hash
	if f, ok := v.(float64); ok {
		if f < math.MinInt64 || f > math.MaxInt64 {
			return 0, fmt.Errorf("float64 out of int64 range: %f", f)
		}
		if f != math.Trunc(f) {
			return 0, fmt.Errorf("float64 has fractional part: %f", f)
		}
	}
	return x, nil
}

// checkUint32Range validates that a non-negative int64 value fits in uint32.
func checkUint32Range(v int64) (uint32, error) {
	if v < 0 {
		return 0, fmt.Errorf("negative value: %d", v)
	}
	if v > math.MaxUint32 {
		return 0, fmt.Errorf("uint32 overflow: %d", v)
	}
	return uint32(v), nil
}

// toBlockHashPtr converts a single block hash (can be nil) to *int64
func toBlockHashPtr(v any) (*int64, error) {
	if v == nil {
		return nil, nil
	}
	hash, err := parseBlockHashToInt64(v)
	if err != nil {
		return nil, err
	}
	return &hash, nil
}

// parseUint32 parses various numeric types to uint32.
// Uses common toInt64 converter and checkUint32Range for validation.
func parseUint32(v any) (uint32, error) {
	x, ok := toInt64(v)
	if !ok {
		return 0, fmt.Errorf("unsupported numeric type %T", v)
	}
	// float64 needs fractional check
	if f, ok := v.(float64); ok {
		if f != math.Trunc(f) {
			return 0, fmt.Errorf("float64 has fractional part: %f", f)
		}
	}
	return checkUint32Range(x)
}

// parseInt parses various numeric types to int.
// Uses common toInt64 converter. Note: float64 truncates toward zero.
func parseInt(v any) (int, error) {
	x, ok := toInt64(v)
	if !ok {
		return 0, fmt.Errorf("unsupported type %T", v)
	}
	if x < math.MinInt || x > math.MaxInt {
		return 0, fmt.Errorf("int overflow: %d", x)
	}
	return int(x), nil
}

// convertTokenIDsToBlocks groups tokenIDs into blocks and converts each block to []byte.
// Each uint32 token is encoded as 4 bytes in big-endian format.
func convertTokenIDsToBlocks(tokenIDs []uint32, blockSize int) ([][]byte, error) {
	if len(tokenIDs) == 0 {
		return [][]byte{}, nil
	}

	if blockSize <= 0 {
		return nil, fmt.Errorf("blockSize must be > 0, got %d", blockSize)
	}

	// Handle non-divisible token count - create a partial final block
	numFullBlocks := len(tokenIDs) / blockSize
	hasPartialBlock := len(tokenIDs)%blockSize != 0
	numBlocks := numFullBlocks
	if hasPartialBlock {
		numBlocks++
	}

	result := make([][]byte, 0, numBlocks)

	// Process full blocks
	for i := 0; i < numFullBlocks; i++ {
		start := i * blockSize
		end := start + blockSize
		result = append(result, tokenIDsToBytes(tokenIDs[start:end]))
	}

	// Process partial block if exists
	if hasPartialBlock {
		start := numFullBlocks * blockSize
		result = append(result, tokenIDsToBytes(tokenIDs[start:]))
	}

	return result, nil
}

// tokenIDsToBytes converts slice of uint32 to big-endian []byte (4 bytes per token).
func tokenIDsToBytes(ids []uint32) []byte {
	out := make([]byte, len(ids)*4)
	for i, v := range ids {
		binary.BigEndian.PutUint32(out[i*4:], v)
	}
	return out
}
