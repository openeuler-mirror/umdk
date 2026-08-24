/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Redis synchronization for prefix cache.
 * Create: 2026-05-21
 */

package prefixcache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	envRedisEnabled    = false
	envRedisKeyPrefix  = "aigw"
	envRedisTTLSeconds = 3600
)

type RedisSync struct {
	client    *redis.Client
	keyPrefix string
	ttl       time.Duration
}

func NewRedisSync(client *redis.Client) *RedisSync {
	return &RedisSync{
		client:    client,
		keyPrefix: envRedisKeyPrefix,
		ttl:       time.Duration(envRedisTTLSeconds) * time.Second,
	}
}

type InstanceEntry struct {
	Name        string `json:"name"`
	LastAccess  int64  `json:"last_access"`
}

func (r *RedisSync) SyncPrefixUpdate(ctx context.Context, ctxKey ModelContext, updates []struct {
	hash     uint64
	instance string
}) error {
	if r.client == nil {
		return nil
	}

	key := r.getContextKey(ctxKey)
	pipe := r.client.Pipeline()
	now := time.Now().Unix()

	for _, update := range updates {
		field := fmt.Sprintf("%d", update.hash)

		val, err := r.client.HGet(ctx, key, field).Result()
		var instances []InstanceEntry
		if err == nil {
			json.Unmarshal([]byte(val), &instances)
		}

		found := false
		for i, inst := range instances {
			if inst.Name == update.instance {
				instances[i].LastAccess = now
				found = true
				break
			}
		}
		if !found {
			instances = append(instances, InstanceEntry{
				Name:       update.instance,
				LastAccess: now,
			})
		}

		data, _ := json.Marshal(instances)
		pipe.HSet(ctx, key, field, data)
	}

	pipe.Expire(ctx, key, r.ttl)
	_, err := pipe.Exec(ctx)
	return err
}

func (r *RedisSync) SyncHashMapping(ctx context.Context, ctxKey ModelContext, engineHash int64, aigwHash uint64) error {
	if r.client == nil {
		return nil
	}

	key := r.getMappingKey(ctxKey)
	field := fmt.Sprintf("%d", engineHash)
	value := fmt.Sprintf("%d", aigwHash)

	pipe := r.client.Pipeline()
	pipe.HSet(ctx, key, field, value)
	pipe.Expire(ctx, key, r.ttl)
	_, err := pipe.Exec(ctx)
	return err
}

func (r *RedisSync) LoadFromRedis(ctx context.Context) (map[ModelContext]map[uint64][]string, error) {
	if r.client == nil {
		return nil, nil
	}

	result := make(map[ModelContext]map[uint64][]string)

	pattern := fmt.Sprintf("%s:prefix:*", r.keyPrefix)
	iter := r.client.Scan(ctx, 0, pattern, 0).Iterator()

	for iter.Next(ctx) {
		key := iter.Val()
		ctxKey := r.parseContextFromKey(key)
		if ctxKey.ModelName == "" {
			continue
		}

		entries, err := r.client.HGetAll(ctx, key).Result()
		if err != nil {
			continue
		}

		prefixMap := make(map[uint64][]string)
		for field, data := range entries {
			var instances []InstanceEntry
			if err := json.Unmarshal([]byte(data), &instances); err != nil {
				continue
			}

			hash := uint64(0)
			fmt.Sscanf(field, "%d", &hash)

			instanceNames := make([]string, 0, len(instances))
			for _, inst := range instances {
				instanceNames = append(instanceNames, inst.Name)
			}
			prefixMap[hash] = instanceNames
		}

		result[ctxKey] = prefixMap
	}

	return result, nil
}

func (r *RedisSync) getContextKey(ctx ModelContext) string {
	return fmt.Sprintf("%s:prefix:%s:%d", r.keyPrefix, ctx.ModelName, ctx.LoraID)
}

func (r *RedisSync) getMappingKey(ctx ModelContext) string {
	return fmt.Sprintf("%s:mapping:%s:%d", r.keyPrefix, ctx.ModelName, ctx.LoraID)
}

func (r *RedisSync) parseContextFromKey(key string) ModelContext {
	var ctx ModelContext
	var modelName string
	var loraID int64

	_, err := fmt.Sscanf(key, fmt.Sprintf("%s:prefix:%%s:%%d", r.keyPrefix), &modelName, &loraID)
	if err != nil {
		return ModelContext{}
	}

	ctx.ModelName = modelName
	ctx.LoraID = loraID
	return ctx
}
