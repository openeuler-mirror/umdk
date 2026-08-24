/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: KV Events handler implementation.
 * Create: 2026-05-21
 */

package kvevents

import (
	"context"
	"huawei.com/aigw/pkg/log"
)

type eventHandler struct {
	manager      *KVEventsManager
	instanceName string
	modelName    string
}

func newEventHandler(manager *KVEventsManager, instanceName, modelName string) *eventHandler {
	return &eventHandler{
		manager:      manager,
		instanceName: instanceName,
		modelName:    modelName,
	}
}

func (h *eventHandler) handleEvent(event Event) error {
	if event == nil {
		log.Warn().Msgf("[kvevents] handleEvent received nil event")
		return nil
	}

	ctx := context.Background()
	log.Debug().Msgf("[kvevents] handleEvent: type=%T, instance=%s", event, h.instanceName)

	switch e := event.(type) {
	case *BlockStored:
		if e == nil {
			log.Warn().Msgf("[kvevents] BlockStored event is nil")
			return nil
		}
		return h.handleBlockStored(ctx, e)
	case *BlockRemoved:
		if e == nil {
			log.Warn().Msgf("[kvevents] BlockRemoved event is nil")
			return nil
		}
		return h.handleBlockRemoved(ctx, e)
	case *AllBlocksCleared:
		if e == nil {
			log.Warn().Msgf("[kvevents] AllBlocksCleared event is nil")
			return nil
		}
		return h.handleAllBlocksCleared(ctx, e)
	default:
		log.Warn().Msgf("[kvevents] unknown event type: %T", event)
		return nil
	}
}

func (h *eventHandler) handleBlockStored(ctx context.Context, event *BlockStored) error {
	log.Debug().Msgf("[kvevents] handleBlockStored called: instance=%s, blocks=%d", h.instanceName, len(event.BlockHashes))

	if h.manager.handler == nil {
		return nil
	}

	event.ModelName = h.modelName
	event.InstanceName = h.instanceName

	if err := h.manager.handler.OnBlockStored(*event); err != nil {
		log.Error().Msgf("[kvevents] failed to handle BlockStored for %s: %v", h.instanceName, err)
		return err
	}

	log.Debug().Msgf("[kvevents] processed BlockStored: %d blocks for %s",
		len(event.BlockHashes), h.instanceName)
	return nil
}

func (h *eventHandler) handleBlockRemoved(ctx context.Context, event *BlockRemoved) error {
	if h.manager.handler == nil {
		return nil
	}

	event.ModelName = h.modelName
	event.InstanceName = h.instanceName

	if err := h.manager.handler.OnBlockRemoved(*event); err != nil {
		log.Error().Msgf("[kvevents] failed to handle BlockRemoved for %s: %v", h.instanceName, err)
		return err
	}

	log.Debug().Msgf("[kvevents] processed BlockRemoved: %d blocks for %s",
		len(event.BlockHashes), h.instanceName)
	return nil
}

func (h *eventHandler) handleAllBlocksCleared(ctx context.Context, event *AllBlocksCleared) error {
	if h.manager.handler == nil {
		return nil
	}

	event.ModelName = h.modelName
	event.InstanceName = h.instanceName

	if err := h.manager.handler.OnAllBlocksCleared(*event); err != nil {
		log.Error().Msgf("[kvevents] failed to handle AllBlocksCleared for %s: %v", h.instanceName, err)
		return err
	}

	log.Debug().Msgf("[kvevents] processed AllBlocksCleared for %s", h.instanceName)
	return nil
}
