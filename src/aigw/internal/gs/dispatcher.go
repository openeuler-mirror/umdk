/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: dispatching schedule request.
 * Create: 2025-05-13
 */

// Package gs is the global scheduler for gateway.
package gs

import (
	"context"
	"fmt"
	"sync"

	"huawei.com/aigw/pkg/log"
)

type dispatchType int

const (
	dispatchRequest dispatchType = iota
	dispatchMigration
	dispatchKvcCopy
)

type globalScheduleDispatcher struct {
	ctx          context.Context
	cancel       context.CancelFunc
	wg           *sync.WaitGroup
	dispatchChan chan *ControlMessage
}

func newGlobalScheduleDispatcher(pctx context.Context) *globalScheduleDispatcher {
	dispatch := &globalScheduleDispatcher{
		dispatchChan: make(chan *ControlMessage, chanBufferSize),
		wg:           new(sync.WaitGroup),
	}

	dispatch.ctx, dispatch.cancel = context.WithCancel(pctx)

	return dispatch
}

func (d *globalScheduleDispatcher) start() {
	log.Info().Msgf("starting dispatcher")

	d.wg.Add(1)
	go d.dispatchLoop()

	log.Info().Msgf("start dispatcher successfully")
}

func (d *globalScheduleDispatcher) stop() {
	log.Info().Msgf("stopping dispatcher")
	d.cancel()

	d.wg.Wait()
	log.Info().Msgf("stop dispatcher successfully")
}

func (d *globalScheduleDispatcher) dispatchLoop() {
	defer d.wg.Done()
	for {
		select {
		case msg := <-d.dispatchChan:
			switch request := msg.Request.(type) {
			case *ExecuteDispatchMsg:
				d.executeDispatching(request.Result, msg.Response)

			default:
				log.Warn().Msgf("unknown dispatch message type: %f", request)
				msg.Response <- fmt.Errorf("unknown dispatch message type: %f", request)
			}
		case <-d.ctx.Done():
			log.Info().Msg("GS schedule dispatch loop was stopped")
			return
		}
	}
}

func (d *globalScheduleDispatcher) executeDispatching(result *scheduleResult, response chan<- interface{}) {
	if result == nil {
		log.Debug().Msgf("schedule result is empty")
		response <- &SuggestionResultMsg{
			PrefillUrl: "",
			DecodeUrl:  "",
		}
		return
	}

	log.Debug().Msgf("send result to MSG, result: prefillUrl %v, decodeUrl %v", result.prefillUrl, result.decodeUrl)
	response <- &SuggestionResultMsg{
		PrefillUrl: result.prefillUrl,
		DecodeUrl:  result.decodeUrl,
	}
}
