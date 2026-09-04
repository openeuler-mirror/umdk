/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: ZMQ client for KV Events subscription.
 * Create: 2026-05-21
 */

package kvevents

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	zmq "github.com/pebbe/zmq4"
	"github.com/vmihailenco/msgpack/v5"
	"huawei.com/aigw/pkg/log"
)

type ZMQClient struct {
	config       ZMQConfig
	instanceName string
	modelName    string

	ctx    *zmq.Context
	socket *zmq.Socket

	mu        sync.RWMutex
	running   bool
	connected bool
	lastSeq   int64

	eventCh           chan EventBatch
	errCh             chan error
	reconnectAttempts int64
}

func NewZMQClient(config ZMQConfig, instanceName, modelName string) (*ZMQClient, error) {
	ctx, err := zmq.NewContext()
	if err != nil {
		return nil, fmt.Errorf("failed to create zmq context: %w", err)
	}

	client := &ZMQClient{
		config:       config,
		instanceName: instanceName,
		modelName:    modelName,
		ctx:          ctx,
		eventCh:      make(chan EventBatch, 100),
		errCh:        make(chan error, 10),
	}

	if err := client.connect(); err != nil {
		ctx.Term()
		return nil, err
	}

	return client, nil
}

func (c *ZMQClient) connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	socket, err := c.ctx.NewSocket(zmq.SUB)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}

	if c.config.HWM > 0 {
		socket.SetRcvhwm(c.config.HWM)
	}

	if err := socket.SetTcpKeepalive(1); err != nil {
		log.Warn().Msgf("failed to set TCP keepalive: %v", err)
	}

	if err := socket.Connect(c.config.Endpoint); err != nil {
		socket.Close()
		return fmt.Errorf("failed to connect to %s: %w", c.config.Endpoint, err)
	}

	// Always set a subscription. A ZMQ SUB socket with no subscription receives
	// NOTHING. SetSubscribe("") subscribes to all messages (ZMQ wildcard),
	// matching vLLM, which publishes with an empty topic frame; a non-empty
	// topic subscribes to that prefix.
	if err := socket.SetSubscribe(c.config.Topic); err != nil {
		socket.Close()
		return fmt.Errorf("failed to subscribe to topic: %w", err)
	}

	c.socket = socket
	c.connected = true
	c.lastSeq = -1

	log.Info().Msgf("[kvevents] connected to %s for instance %s", c.config.Endpoint, c.instanceName)
	return nil
}

// reconnect tears down the current socket and re-establishes the connection
// in a bounded retry loop. It observes ctx so that a peer that stays down
// cannot pin the receiveLoop goroutine forever — without the ctx check, a
// long-lived vLLM outage would block the single receive goroutine inside this
// loop and Stop()'s graceful shutdown would never be observed.
func (c *ZMQClient) reconnect(ctx context.Context) {
	c.mu.Lock()
	if c.connected && c.socket != nil {
		c.socket.Close()
		c.connected = false
	}
	c.mu.Unlock()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msgf("[kvevents] reconnect cancelled for %s: %v", c.instanceName, ctx.Err())
			return
		case <-time.After(c.config.ReconnectDelay):
		}

		if err := c.connect(); err != nil {
			log.Error().Msgf("[kvevents] reconnect failed for %s: %v", c.instanceName, err)
			continue
		}

		log.Info().Msgf("[kvevents] reconnected to %s", c.instanceName)
		return
	}
}

func (c *ZMQClient) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = true
	c.mu.Unlock()

	go c.receiveLoop(ctx)
	return nil
}

func (c *ZMQClient) receiveLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			batch, err := c.receive()
			if err != nil {
				log.Error().Msgf("[kvevents] receive error from %s: %v", c.instanceName, err)
				select {
				case c.errCh <- err:
				default:
				}
				// Fatal ZMQ errors (context terminated, socket closed) leave
				// the socket unusable. The previous receiveLoop retried on
				// the same dead socket forever — the dead reconnectCh meant
				// no path ever triggered reconnect(), so a restarted vLLM
				// silently starved the prefix-cache index for that instance.
				// Now: classify the error and reconnect on fatal failures.
				if isFatalRecvError(err) {
					atomic.AddInt64(&c.reconnectAttempts, 1)
					log.Warn().Msgf("[kvevents] fatal ZMQ error from %s, triggering reconnect (attempt %d)",
						c.instanceName, c.ReconnectAttempts())
					c.reconnect(ctx)
				}
				continue
			}
			if batch != nil {
				select {
				case c.eventCh <- *batch:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (c *ZMQClient) receive() (*EventBatch, error) {
	c.mu.RLock()
	socket := c.socket
	c.mu.RUnlock()

	if socket == nil {
		return nil, fmt.Errorf("socket not connected")
	}

	poller := zmq.NewPoller()
	poller.Add(socket, zmq.POLLIN)

	polled, err := poller.Poll(c.config.PollTimeout)
	if err != nil {
		return nil, fmt.Errorf("poll error: %w", err)
	}
	if len(polled) == 0 {
		return nil, nil
	}

	msg, err := socket.RecvMessageBytes(0)
	if err != nil {
		return nil, fmt.Errorf("recv error: %w", err)
	}

	log.Debug().Msgf("[kvevents] received ZMQ message with %d parts for %s", len(msg), c.instanceName)

	if len(msg) < 3 {
		return nil, fmt.Errorf("invalid message: expected at least 3 parts, got %d", len(msg))
	}

	seq := int64(0)
	if len(msg[1]) == 8 {
		seq = int64(binary.BigEndian.Uint64(msg[1]))
	}

	if c.lastSeq >= 0 && seq > c.lastSeq+1 {
		log.Warn().Msgf("[kvevents] sequence gap detected for %s: expected %d, got %d",
			c.instanceName, c.lastSeq+1, seq)
	}

	batch, err := c.decodeBatch(msg[2], seq)
	if err != nil {
		return nil, fmt.Errorf("decode error: %w", err)
	}

	c.lastSeq = seq
	return batch, nil
}

func (c *ZMQClient) decodeBatch(data []byte, seq int64) (*EventBatch, error) {
	// vLLM 0.18 emits a msgpack array batch with 2 or 3 elements:
	//   [timestamp(float64), events]               (legacy 2-field)
	//   [timestamp(float64), events, dp_rank(int)] (vLLM 0.18+, 3-field)
	// Decode leniently as []interface{} so neither the field count nor the
	// float64 timestamp breaks decoding (a 2-field struct was rejected by
	// vmihailenco msgpack with "number of fields in array-encoded struct
	// has changed", silently dropping every real vLLM event).
	var rawBatch []interface{}
	if err := msgpack.Unmarshal(data, &rawBatch); err != nil {
		return nil, fmt.Errorf("msgpack decode error: %w", err)
	}
	if len(rawBatch) < 2 {
		return nil, fmt.Errorf("malformed kv-event batch: len=%d, want >= 2", len(rawBatch))
	}

	batch := &EventBatch{
		Timestamp: seq, // use ZMQ sequence number as the authoritative batch ts
	}

	// optional third field: data-parallel rank (vLLM 0.18+)
	if len(rawBatch) >= 3 {
		if dpr, ok := toInt64(rawBatch[2]); ok {
			batch.DataParallelRank = int(dpr)
		}
	}

	eventsRaw, ok := rawBatch[1].([]interface{})
	if !ok {
		return nil, fmt.Errorf("malformed kv-event batch: events field type=%T", rawBatch[1])
	}
	batch.Events = make([]Event, 0, len(eventsRaw))

	for _, raw := range eventsRaw {
		rawEvent, ok := raw.([]interface{})
		if !ok || len(rawEvent) == 0 {
			continue
		}

		eventType, ok := rawEvent[0].(string)
		if !ok {
			log.Warn().Msgf("[kvevents] rawEvent[0] is not string, type=%T", rawEvent[0])
			continue
		}

		var event Event
		switch eventType {
		case "BlockStored":
			event = c.decodeBlockStored(rawEvent[1:], seq)
		case "BlockRemoved":
			event = c.decodeBlockRemoved(rawEvent[1:], seq)
		case "AllBlocksCleared":
			event = &AllBlocksCleared{
				ModelName:    c.modelName,
				InstanceName: c.instanceName,
				Timestamp:    time.UnixMilli(seq),
			}
		}

		if event != nil {
			batch.Events = append(batch.Events, event)
		} else {
			log.Warn().Msgf("[kvevents] event is nil for type=%s", eventType)
		}
	}

	return batch, nil
}

func (c *ZMQClient) decodeBlockStored(raw []interface{}, seq int64) *BlockStored {
	if len(raw) < 5 {
		log.Warn().Msgf("[kvevents] decodeBlockStored: raw too short, len=%d, need 5", len(raw))
		return nil
	}

	event := &BlockStored{
		ModelName:    c.modelName,
		InstanceName: c.instanceName,
		Timestamp:    time.UnixMilli(seq),
	}

	// 0: BlockHashes - support both int64 (legacy) and []byte (SHA-256)
	event.BlockHashes = parseBlockHashes(raw[0])

	// 1: ParentBlockHash - use toInt64 from msgpack_decoder.go
	if raw[1] != nil {
		if ph, ok := toInt64(raw[1]); ok {
			event.ParentBlockHash = &ph
		} else {
			log.Warn().Msgf("[kvevents] decodeBlockStored: ParentBlockHash unexpected type %T", raw[1])
		}
	}

	// 2: TokenIDs - flat list of uint32, need to group by blockSize
	// Get blockSize from raw[3]
	blockSize := 16
	if bs, err := parseInt(raw[3]); err == nil && bs > 0 {
		blockSize = bs
	}
	log.Debug().Msgf("[kvevents] parsed blockSize=%d", blockSize)

	event.TokenIDs = parseTokenIDs(raw[2], blockSize)

	if log.DebugEnabled() {
		log.Debug().Msgf("[kvevents] after parseTokenIDs: len(TokenIDs)=%d (should be num blocks)", len(event.TokenIDs))
		if len(event.TokenIDs) > 0 {
			log.Debug().Msgf("[kvevents] TokenIDs[0] len=%d hex=%x", len(event.TokenIDs[0]), event.TokenIDs[0])
			if len(event.TokenIDs) > 1 {
				log.Debug().Msgf("[kvevents] TokenIDs[1] len=%d hex=%x", len(event.TokenIDs[1]), event.TokenIDs[1])
			}
		}
	}

	// 3: BlockSize (keep for backward compatibility, though we get it from config now)
	// Now unused - we read from config

	// 4: LoraID - use toInt64 from msgpack_decoder.go
	// Note: msgpack encodes small integers as fixint (-32 to 127), so -1 decodes as int8
	if raw[4] != nil {
		if loraID, ok := toInt64(raw[4]); ok {
			event.LoraID = loraID
		} else {
			log.Warn().Msgf("[kvevents] decodeBlockStored: LoraID unexpected type %T", raw[4])
		}
	}

	log.Debug().Msgf("[kvevents] decodeBlockStored: blockSize=%d, LoraID=%d, BlockHashes=%d, TokenIDs blocks=%d",
		blockSize, event.LoraID, len(event.BlockHashes), len(event.TokenIDs))

	return event
}

// parseBlockHashes parses block hashes supporting multiple formats.
// Uses toBlockHashSlice for []interface{} to share the same element-type logic
// as the primary msgpack decoder. Other homogeneous slices are converted directly.
func parseBlockHashes(v interface{}) []int64 {
	switch x := v.(type) {
	case []interface{}:
		// Delegate to msgpack_decoder.go which handles all element types
		if hashes, err := toBlockHashSlice(x); err == nil {
			return hashes
		}
		return []int64{}
	case []int64:
		return x
	case []int:
		hashes := make([]int64, len(x))
		for i, h := range x {
			hashes[i] = int64(h)
		}
		return hashes
	case []uint64:
		hashes := make([]int64, len(x))
		for i, h := range x {
			hashes[i] = int64(h)
		}
		return hashes
	case []float64:
		hashes := make([]int64, len(x))
		for i, h := range x {
			hashes[i] = int64(h)
		}
		return hashes
	default:
		log.Warn().Msgf("[kvevents] parseBlockHashes: unsupported type %T", v)
		return []int64{}
	}
}

// parseTokenIDs parses flat token ID list and groups into blocks.
// Input: flat list of integers (decoded from msgpack as various numeric types)
// Output: [][]byte where each []byte is blockSize tokens * 4 bytes (uint32 big-endian)
// Block grouping is delegated to convertTokenIDsToBlocks from msgpack_decoder.go.
func parseTokenIDs(v interface{}, blockSize int) [][]byte {
	var tokenIDs []uint32

	switch x := v.(type) {
	case []interface{}:
		tokenIDs = make([]uint32, 0, len(x))
		for _, item := range x {
			if tid, err := parseUint32(item); err == nil {
				tokenIDs = append(tokenIDs, tid)
			}
		}
	case []int64:
		tokenIDs = make([]uint32, len(x))
		for i, t := range x {
			tokenIDs[i] = uint32(t)
		}
	case []int:
		tokenIDs = make([]uint32, len(x))
		for i, t := range x {
			tokenIDs[i] = uint32(t)
		}
	case []uint32:
		tokenIDs = x
	case []uint64:
		tokenIDs = make([]uint32, len(x))
		for i, t := range x {
			tokenIDs[i] = uint32(t)
		}
	case []float64:
		tokenIDs = make([]uint32, len(x))
		for i, t := range x {
			tokenIDs[i] = uint32(int64(t))
		}
	default:
		log.Warn().Msgf("[kvevents] parseTokenIDs: unsupported type %T", v)
		return [][]byte{}
	}

	// Delegate block grouping to msgpack_decoder.go
	result, err := convertTokenIDsToBlocks(tokenIDs, blockSize)
	if err != nil {
		log.Warn().Msgf("[kvevents] parseTokenIDs: convertTokenIDsToBlocks failed: %v", err)
		return [][]byte{}
	}
	return result
}

func (c *ZMQClient) decodeBlockRemoved(raw []interface{}, seq int64) *BlockRemoved {
	// AIBRIX format: raw[0] = block_hashes
	// Note: AIBRIX BlockRemoved doesn't include LoraID, default to -1 to match BlockStored
	if len(raw) < 1 {
		return nil
	}

	event := &BlockRemoved{
		ModelName:    c.modelName,
		InstanceName: c.instanceName,
		LoraID:       -1, // Default to -1 to match BlockStored
		Timestamp:    time.UnixMilli(seq),
	}

	// All block hash parsing delegated to parseBlockHashes (uses toBlockHashSlice internally)
	event.BlockHashes = parseBlockHashes(raw[0])

	// Debug logging for troubleshooting
	log.Debug().Msgf("[kvevents] decodeBlockRemoved: processed BlockHashes len=%d, LoraID=%d, model=%s, instance=%s",
		len(event.BlockHashes), event.LoraID, event.ModelName, event.InstanceName)

	return event
}

func (c *ZMQClient) Events() <-chan EventBatch {
	return c.eventCh
}

func (c *ZMQClient) Errors() <-chan error {
	return c.errCh
}

func (c *ZMQClient) Stop() {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return
	}
	c.running = false

	if c.socket != nil {
		c.socket.Close()
		c.socket = nil
	}
	c.connected = false
	c.mu.Unlock()

	log.Info().Msgf("[kvevents] stopped for instance %s", c.instanceName)
}

func (c *ZMQClient) Close() {
	c.Stop()

	c.mu.Lock()
	if c.ctx != nil {
		c.ctx.Term()
		c.ctx = nil
	}
	c.mu.Unlock()
}
