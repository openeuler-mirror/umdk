/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: KV Events types and interfaces for AIGW prefix cache.
 * Create: 2026-05-21
 */

package kvevents

import (
	"time"
)

type EventType string

const (
	EventTypeBlockStored   EventType = "BlockStored"
	EventTypeBlockRemoved  EventType = "BlockRemoved"
	EventTypeAllBlocksCleared EventType = "AllBlocksCleared"
)

type Event interface {
	GetType() EventType
	GetModelName() string
	GetInstanceName() string
}

// BlockStored represents a vLLM BlockStored event.
// TokenIDs is already grouped into blocks, each []byte contains blockSize tokens encoded as uint32 big-endian (4 bytes per token).
type BlockStored struct {
	BlockHashes     []int64 // Supports both int64 (legacy) and []byte (SHA-256, first 8 bytes used)
	ParentBlockHash *int64
	// TokenIDs: [][]byte where each element is one block's tokens as bytes.
	// Each block contains blockSize tokens, each token encoded as 4 bytes big-endian uint32.
	// Total bytes per block = blockSize * 4.
	TokenIDs     [][]byte
	LoraID       int64
	ModelName    string
	InstanceName string
	SourcePod    string // Pod that stored these blocks
	Timestamp    time.Time
}

func (e *BlockStored) GetType() EventType        { return EventTypeBlockStored }
func (e *BlockStored) GetModelName() string      { return e.ModelName }
func (e *BlockStored) GetInstanceName() string   { return e.InstanceName }

type BlockRemoved struct {
	BlockHashes  []int64
	LoraID       int64
	ModelName    string
	InstanceName string
	SourcePod    string // Pod that removed these blocks
	Timestamp    time.Time
}

func (e *BlockRemoved) GetType() EventType      { return EventTypeBlockRemoved }
func (e *BlockRemoved) GetModelName() string    { return e.ModelName }
func (e *BlockRemoved) GetInstanceName() string { return e.InstanceName }

type AllBlocksCleared struct {
	ModelName    string
	InstanceName string
	SourcePod    string // Pod that cleared all blocks
	Timestamp    time.Time
}

func (e *AllBlocksCleared) GetType() EventType      { return EventTypeAllBlocksCleared }
func (e *AllBlocksCleared) GetModelName() string    { return e.ModelName }
func (e *AllBlocksCleared) GetInstanceName() string { return e.InstanceName }

type EventBatch struct {
	Timestamp        int64
	Events           []Event
	DataParallelRank int
}

type ZMQConfig struct {
	Endpoint       string
	Topic          string
	PollTimeout    time.Duration
	ReconnectDelay time.Duration
	HWM            int
}

type EventHandler interface {
	OnBlockStored(event BlockStored) error
	OnBlockRemoved(event BlockRemoved) error
	OnAllBlocksCleared(event AllBlocksCleared) error
}
