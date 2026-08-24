/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: ZMQ client decode tests with real vLLM 0.18 event bytes.
 */

package kvevents

import (
	_ "embed"
	"testing"
)

//go:embed testdata/blockstored_vllm_real.bin
var realBlockStoredBatch []byte

// TestZMQClient_DecodeBatch_RealVLLMEvent feeds a real vLLM 0.18 KVEventBatch
// (captured from a ZMQ PUB on tcp://*:5557, block_size=128, Qwen2.5-7B-Instruct)
// through decodeBatch.
//
// vLLM emits a 3-element array batch [ts(float64), events, data_parallel_rank(int 0)].
// aigw's previous decodeBatch used a 2-field anonymous struct (Timestamp int64 +
// Events), which vmihailenco msgpack rejected with
// "number of fields in array-encoded struct has changed" — silently dropping every
// real vLLM event. This test pins lenient decoding of vLLM's wire format.
func TestZMQClient_DecodeBatch_RealVLLMEvent(t *testing.T) {
	c := &ZMQClient{modelName: "Qwen2.5-7B-Instruct", instanceName: "vllm-1"}

	batch, err := c.decodeBatch(realBlockStoredBatch, 1700000000000)
	if err != nil {
		t.Fatalf("decodeBatch failed: %v", err)
	}
	if len(batch.Events) != 1 {
		t.Fatalf("want 1 event, got %d (batch=%+v)", len(batch.Events), batch)
	}

	bs, ok := batch.Events[0].(*BlockStored)
	if !ok {
		t.Fatalf("event[0] is %T, want *BlockStored", batch.Events[0])
	}
	if bs.ModelName != "Qwen2.5-7B-Instruct" || bs.InstanceName != "vllm-1" {
		t.Fatalf("model/instance not propagated: model=%q instance=%q", bs.ModelName, bs.InstanceName)
	}
	if len(bs.BlockHashes) < 1 {
		t.Fatalf("BlockHashes empty")
	}
	if len(bs.TokenIDs) != len(bs.BlockHashes) {
		t.Fatalf("TokenIDs blocks %d != BlockHashes %d", len(bs.TokenIDs), len(bs.BlockHashes))
	}
	// LoraID decodes from a nil field → 0 (no LoRA on this request).
	if bs.LoraID != 0 {
		t.Fatalf("LoraID = %d, want 0 (vLLM sent nil)", bs.LoraID)
	}
}
