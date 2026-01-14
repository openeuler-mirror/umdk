/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: inference instance management.
 * Create: 2025-05-13
 */

// Package gs is the global scheduler for AIGW.
package gs

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"huawei.com/aigw/pkg/crypto"
	"huawei.com/aigw/pkg/log"
	"huawei.com/aigw/pkg/utils"
)

const (
	timeInterval    = 300 * time.Millisecond
	retryTimes      = 5
	printLogEvery   = 5
	defaultMaxDelay = 16
	connectTimeout  = 200 * time.Millisecond
)

// Watcher interface
type instanceWatcher interface {
	connect() error
	run(wg *sync.WaitGroup)
	connectWithRetry() error
	checkConnAndRetry() error
	isHealth() bool // check this watch is ok or not
	setHealth()
}

// sseWatcher connect to inferInstance by sse
type sseWatcher struct {
	targetUrl  string
	msgChan    chan string
	retryCount uint32
	insCtx     context.Context
	hmacMgr    *crypto.HmacManager
	aesMgr     *crypto.AesManager
	client     *http.Client
	resp       *http.Response
	scanner    *bufio.Scanner
	enable     bool
	maxDelay   int
	tryRecover bool // flag used to indicate that sseWatcher try to recover abnormal connection
	ins        *instance
	sync.Mutex
}

func newSseWatcher(ins *instance) *sseWatcher {
	return &sseWatcher{
		targetUrl:  "http://" + ins.insUrl + "/subscribe-event",
		msgChan:    ins.msgChan,
		retryCount: 0,
		insCtx:     ins.ctx,
		hmacMgr:    ins.insMgr.hmacMgr,
		aesMgr:     ins.insMgr.aesMgr,
		client:     &http.Client{},
		enable:     false,
		maxDelay:   defaultMaxDelay,
		tryRecover: false,
		ins:        ins,
	}
}

func (w *sseWatcher) connectWithRetry() error {
	var err error
	for i := 0; i < retryTimes; i++ {
		err = w.connect()
		if err == nil {
			w.enable = true
			return nil
		}
		w.enable = false
		log.WarnAlarmMsgf(log.InstanceConnTimeout, log.Report, fmt.Sprintf("%v sse connect failed, retrying...", w.targetUrl))
		time.Sleep(timeInterval)
	}
	return err
}

func (w *sseWatcher) connect() error {
	if w.insCtx.Err() != nil {
		return w.insCtx.Err()
	}

	connectCtx, cancel := context.WithCancel(w.insCtx)
	req, err := http.NewRequestWithContext(connectCtx, "GET", w.targetUrl, nil)
	if err != nil {
		log.Error().Msgf("[insWatcher]Error creating request for %s: %v", w.targetUrl, err)
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	if w.hmacMgr.EnableHmac() {
		er := w.hmacMgr.AddHmacSign(req, "")
		if er != nil {
			return er
		}
	}

	connectChan := make(chan error, 1)
	go func() {
		resp, err := w.client.Do(req)

		if err != nil {
			connectChan <- fmt.Errorf("[insWatcher]Connection error to %s: %v", w.targetUrl, err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			connectChan <- fmt.Errorf("connection error to %s returned status: %d",
				w.targetUrl, resp.StatusCode)
			return
		}

		w.resp = resp
		connectChan <- nil
	}()

	select {
	case <-time.After(connectTimeout):
		cancel()
		return fmt.Errorf("connect timeout")
	case err := <-connectChan:
		if err != nil {
			log.Error().Msgf(" %v", err)
			return err
		}
		w.enable = true
		return nil
	}
}

func (w *sseWatcher) run(wg *sync.WaitGroup) {
	defer wg.Done()
	defer w.resp.Body.Close()
	w.scanner = bufio.NewScanner(w.resp.Body)
	for {
		select {
		case <-w.insCtx.Done(): //  cancel the connection with insWatcher
			log.Info().Msgf("[insWatcher]Closing connection to %v", w.targetUrl)
			return
		default:
			err := w.checkConnAndRetry()
			if err != nil {
				continue
			}
			if w.tryRecover && err == nil {
				w.tryRecover = false
				log.WarnAlarmMsgf(log.InstanceReconnTimeout, log.Clear,
					fmt.Sprintf("Connection with %v has been restored", w.targetUrl))
			}
			line := w.scanner.Text() // read a line of string with as the delimiter by default
			w.msgChan <- line

		}
	}
}

func (w *sseWatcher) checkConnAndRetry() error {
	if w.scanner.Scan() {
		return nil
	}
	if w.insCtx.Err() != nil {
		return w.insCtx.Err()
	}
	if w.enable {
		w.Lock()
		w.enable = false
		w.Unlock()
		log.Debug().Msgf("[watcher]ins %v connection failed, update snapshot immediately", w.ins.insUrl)
		w.ins.insMgr.updatePoolShot() // update snapshot immediately when the connection failed
	}
	if w.retryCount == 0 {
		err := w.resp.Body.Close()
		if err != nil {
			return err
		}
	}
	err := w.connect()
	if err == nil {
		w.scanner = bufio.NewScanner(w.resp.Body)
		w.retryCount = 0
		w.Lock()
		w.enable = true
		w.Unlock()
		log.Debug().Msgf("[watcher]ins %v connection recovery, update snapshot immediately", w.ins.insUrl)
		w.ins.insMgr.updatePoolShot() // update snapshot immediately when the connection recovery
		return nil
	} else {
		// try to reconnect to rtc instances
		w.tryRecover = true
		// Calculate the next retry interval
		backoff := utils.GetExpBackoffDelay(w.retryCount, w.maxDelay)
		w.retryCount++
		// Log is printed every 5 retries.
		if w.retryCount%printLogEvery == 1 {
			log.WarnAlarmMsgf(log.InstanceReconnTimeout, log.Report,
				fmt.Sprintf("Connection closed by server: %v, retrying...", w.targetUrl))
		}
		utils.SleepWithContext(w.insCtx, backoff)
		return err
	}
}

func (w *sseWatcher) isHealth() bool {
	w.Lock()
	defer w.Unlock()
	return w.enable
}

func (w *sseWatcher) setHealth() {
	w.Lock()
	defer w.Unlock()
	w.enable = true
}
