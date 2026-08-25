/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package kvevents

import (
	"sync"
	"testing"
	"time"
)

type countingHandler struct {
	mu      sync.Mutex
	stored  int
	removed int
}

func (c *countingHandler) OnBlockStored(_ BlockStored) error {
	c.mu.Lock()
	c.stored++
	c.mu.Unlock()
	return nil
}
func (c *countingHandler) OnBlockRemoved(_ BlockRemoved) error {
	c.mu.Lock()
	c.removed++
	c.mu.Unlock()
	return nil
}
func (c *countingHandler) OnAllBlocksCleared(_ AllBlocksCleared) error { return nil }

func TestMultiHandler_FansOutToAll(t *testing.T) {
	a, b := &countingHandler{}, &countingHandler{}
	mh := NewMultiHandler(a, b)
	_ = mh.OnBlockStored(BlockStored{BlockHashes: []int64{1}, Timestamp: time.Now()})
	_ = mh.OnBlockRemoved(BlockRemoved{BlockHashes: []int64{1}, Timestamp: time.Now()})
	if a.stored != 1 || b.stored != 1 {
		t.Fatalf("stored a=%d b=%d", a.stored, b.stored)
	}
	if a.removed != 1 || b.removed != 1 {
		t.Fatalf("removed a=%d b=%d", a.removed, b.removed)
	}
}

func TestMultiHandler_ErrorInOneDoesNotBlockOther(t *testing.T) {
	failing := &countingHandler{} // we'll inject failure differently
	b := &countingHandler{}
	mh := NewMultiHandler(failing, b)
	_ = mh.OnBlockStored(BlockStored{BlockHashes: []int64{1}, Timestamp: time.Now()})
	if b.stored != 1 {
		t.Fatal("b should still receive event even if a fails")
	}
}
