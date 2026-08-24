/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package kvevents

import "huawei.com/aigw/pkg/log"

// MultiHandler fans events out to multiple EventHandler instances. It replaces the
// single-handler assumption in KVEventsManager so both prefixcache and KvcSessionManager
// receive BlockStored/BlockRemoved. An error in one handler is logged but does not block
// delivery to the others.
type MultiHandler struct {
	handlers []EventHandler
}

func NewMultiHandler(handlers ...EventHandler) *MultiHandler {
	return &MultiHandler{handlers: handlers}
}

func (m *MultiHandler) OnBlockStored(e BlockStored) error {
	for _, h := range m.handlers {
		if err := h.OnBlockStored(e); err != nil {
			log.Error().Err(err).Msg("[kvevents] one handler failed OnBlockStored")
		}
	}
	return nil
}
func (m *MultiHandler) OnBlockRemoved(e BlockRemoved) error {
	for _, h := range m.handlers {
		if err := h.OnBlockRemoved(e); err != nil {
			log.Error().Err(err).Msg("[kvevents] one handler failed OnBlockRemoved")
		}
	}
	return nil
}
func (m *MultiHandler) OnAllBlocksCleared(e AllBlocksCleared) error {
	for _, h := range m.handlers {
		if err := h.OnAllBlocksCleared(e); err != nil {
			log.Error().Err(err).Msg("[kvevents] one handler failed OnAllBlocksCleared")
		}
	}
	return nil
}
