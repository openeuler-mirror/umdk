//go:build cshared
// +build cshared

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Server provides north interfaces for AIGW.
 * Create: 2026-01-15
 */

// Package main use api for AIGW
package main

/*
#cgo CFLAGS: -I../include
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "aigw.h"

// Auxiliary variable: global ops variable c on the CGO side, used to call the related C callback.
static aigw_cache_driver_ops_t saved_ops;

// Auxiliary function, check callback operations on the C side.
static inline aigw_error_t check_driver_ops(aigw_cache_driver_ops_t *ops) {
	if (ops->hash_get_all == NULL || ops->hash_set_fields == NULL ||
		ops->hash_delete_fields == NULL) {
		return AIGW_ERR_INVALID_PARAM;
	}

	return AIGW_SUCCESS;
}

// Auxiliary function, stores callback operations on the C side.
static inline void save_driver_ops(aigw_cache_driver_ops_t ops) {
	saved_ops = ops;
}

// Auxiliary function, used for the Go side to call the hash_get_all function on the C side.
static inline aigw_error_t call_hash_get_all(char* key, key_value_array_t* out_map) {
	if (saved_ops.hash_get_all != NULL) {
		return saved_ops.hash_get_all(key, out_map);
	}
	return AIGW_ERR_INTERNAL;
}

static inline aigw_error_t call_hash_get_all_batch(const char **keys, uint32_t key_count,
		key_value_array_t *out_arrays) {
    if (saved_ops.hash_get_all_batch != NULL) {
		return saved_ops.hash_get_all_batch(keys, key_count, out_arrays);
	}
	return AIGW_ERR_INTERNAL;
}

// Auxiliary function, used for the Go side to call the hash_set_fields function on the C side.
static inline aigw_error_t call_hash_set_fields(char* key, key_value_array_t *fields) {
	if (saved_ops.hash_set_fields != NULL) {
		return saved_ops.hash_set_fields(key, fields);
	}
	return AIGW_ERR_INTERNAL;
}

// Auxiliary function, used for the Go side to call the hash_delete_fields function on the C side.
static inline aigw_error_t call_hash_delete_fields(char* key, char **field_keys, int field_count) {
	if (saved_ops.hash_delete_fields != NULL) {
		return saved_ops.hash_delete_fields(key, field_keys, field_count);
	}
	return AIGW_ERR_INTERNAL;
}
*/
import "C"
import (
	"fmt"
	"net"
	"strings"
	"unsafe"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/cachecenter"
	"huawei.com/aigw/internal/core"
	"huawei.com/aigw/internal/gs"
	"huawei.com/aigw/internal/server"
	"huawei.com/aigw/pkg/log"
)

var roleMap = map[int]string{
	0: "mixed",
	1: "prefill",
	2: "decode",
}

var lbTypeMap = map[int]string{
	0: "none",
	1: "token",
	2: "prefillTimeAware",
}

var go2cErrMap = map[base.AIGWErrorCode]C.aigw_error_t{
	base.AIGW_SUCCESS:           C.AIGW_SUCCESS,
	base.AIGW_ERR_INVALID_PARAM: C.AIGW_ERR_INVALID_PARAM,
	base.AIGW_ERR_TIMEOUT:       C.AIGW_ERR_TIMEOUT,
	base.AIGW_ERR_NOT_FOUND:     C.AIGW_ERR_NOT_FOUND,
	base.AIGW_ERR_NO_MEMORY:     C.AIGW_ERR_NO_MEMORY,
	base.AIGW_ERR_INTERNAL:      C.AIGW_ERR_INTERNAL,
	base.AIGW_ERR_NO_SPACE:      C.AIGW_ERR_NO_SPACE,
	base.AIGW_ERR_COMP_NOT_INIT: C.AIGW_ERR_COMP_NOT_INIT,
	base.AIGW_ERR_INVALID_STATE: C.AIGW_ERR_INVALID_STATE,
}

var c2goErrMap = map[C.aigw_error_t]base.AIGWErrorCode{
	C.AIGW_SUCCESS:           base.AIGW_SUCCESS,
	C.AIGW_ERR_INVALID_PARAM: base.AIGW_ERR_INVALID_PARAM,
	C.AIGW_ERR_TIMEOUT:       base.AIGW_ERR_TIMEOUT,
	C.AIGW_ERR_NOT_FOUND:     base.AIGW_ERR_NOT_FOUND,
	C.AIGW_ERR_NO_MEMORY:     base.AIGW_ERR_NO_MEMORY,
	C.AIGW_ERR_INTERNAL:      base.AIGW_ERR_INTERNAL,
	C.AIGW_ERR_NO_SPACE:      base.AIGW_ERR_NO_SPACE,
	C.AIGW_ERR_COMP_NOT_INIT: base.AIGW_ERR_COMP_NOT_INIT,
	C.AIGW_ERR_INVALID_STATE: base.AIGW_ERR_INVALID_STATE,
}

const (
	// defaultPredictType default predict type
	defaultPredictType = "none"

	defaultMaxInferenceInstances  = 4096
	defaultMaxConcurrentRequests  = 512
	defaultSnapshotUpdateInterval = 1 // second
)

func str2Char(dst []C.char, src string, charLen int) {
	dstLen := len(dst)
	var i int

	for i = 0; i < dstLen-1 && i < charLen-1 && i < len(src); i++ {
		if src[i] == 0 {
			break
		}
		dst[i] = C.char(src[i])
	}

	if i < dstLen {
		dst[i] = 0
	}
}

func go2cError(err error) C.aigw_error_t {
	if aigwErr, ok := err.(base.AIGWErrorCode); ok {
		if e, exists := go2cErrMap[aigwErr]; exists {
			return e
		}
	}
	return C.AIGW_ERR_INTERNAL
}

func c2goError(err C.aigw_error_t) error {
	if err == C.AIGW_SUCCESS {
		return nil
	}
	if e, exists := c2goErrMap[err]; exists {
		return e
	}
	return base.AIGW_ERR_INTERNAL
}

func aigw_check_state() C.aigw_error_t {
	if !server.IsInitComp() {
		fmt.Printf("ERR: The AIGW library is not initialized.\n")
		return C.AIGW_ERR_COMP_NOT_INIT
	}

	if !server.IsRegCacheDriver() {
		log.Error().Msgf("The cache driver is not registered.")
		return C.AIGW_ERR_INVALID_STATE
	}

	return C.AIGW_SUCCESS
}

//export aigw_init
func aigw_init(cfg *C.aigw_config_t) C.aigw_error_t {
	if cfg == nil || cfg.log_level == nil || cfg.log_path == nil {
		fmt.Printf("ERR: aigw_init failed, err is NULL config pointer\n")
		return C.AIGW_ERR_INVALID_PARAM
	}

	if server.IsInitComp() {
		fmt.Printf("aigw_init failed: component already initialized.\n")
		return C.AIGW_ERR_INVALID_STATE
	}

	logLevel := C.GoString(cfg.log_level)
	logPath := C.GoString(cfg.log_path)
	if strings.TrimSpace(logLevel) == "" || strings.TrimSpace(logPath) == "" {
		fmt.Printf("The logLevel, logPath parameter is incorrect, " +
			"one of them is empty.")
		return C.AIGW_ERR_INVALID_PARAM
	}

	if cfg.request_ttl_seconds < 0 {
		fmt.Printf("request_ttl_second < 0, it is incorrect\n")
		return C.AIGW_ERR_INVALID_PARAM
	}

	compConfig := base.AigwConfig{}
	compConfig.GlobalConfig.LogLevel = logLevel
	compConfig.GlobalConfig.LogPath = logPath
	compConfig.Limits.TotalInsNum = defaultMaxInferenceInstances
	compConfig.GlobalConfig.ReqTimeout = int64(cfg.request_ttl_seconds)
	compConfig.GlobalConfig.SnapshotUpdateInterval = defaultSnapshotUpdateInterval
	compConfig.Limits.InsNumPerModel = int(cfg.max_instances_per_model)
	compConfig.Limits.Concurrency = defaultMaxConcurrentRequests
	compConfig.Limits.MaxPromptRunes = int(cfg.max_prompt_length)
	compConfig.Limits.ModelNum = int(cfg.max_supported_models)
	compConfig.Predictor.PredictType = defaultPredictType

	if err := core.ValidateLimits(&compConfig.Limits); err != nil {
		fmt.Printf("ERR: Failed to validate param, err:%v", err)
		return C.AIGW_ERR_INVALID_PARAM
	}

	if err := server.InitComp(&compConfig); err != nil {
		fmt.Printf("ERR: InitComp failed:%v\n", err)
		return go2cError(err)
	}
	return C.AIGW_SUCCESS
}

//export aigw_uninit
func aigw_uninit() {
	if !server.IsInitComp() {
		fmt.Printf("ERR: The AIGW library is not initialized.\n")
		return
	}

	server.UninitComp()
}

//export aigw_select_nodes
func aigw_select_nodes(req *C.aigw_request_t, ctx *C.aigw_select_context_t,
	out_result *C.aigw_select_result_t) C.aigw_error_t {
	if err := aigw_check_state(); err != C.AIGW_SUCCESS {
		return err
	}

	if req == nil || ctx == nil || out_result == nil ||
		req.uuid == nil || req.model == nil {
		log.Error().Msgf("The req, ctx, or out_result parameter is incorrect, " +
			"one of them is empty.")
		return C.AIGW_ERR_INVALID_PARAM
	}

	// Convert aigw_request_t to OpenAiRequest.
	goReq := base.OpenAiRequest{}
	uuid := C.GoString(req.uuid)
	model := C.GoString(req.model)
	if strings.TrimSpace(uuid) == "" || strings.TrimSpace(model) == "" {
		log.Error().Msgf("The uuid, model parameter is incorrect, " +
			"one of them is empty.")
		return C.AIGW_ERR_INVALID_PARAM
	}
	goReq.UUID = uuid
	goReq.Model = model

	msgCount := int(req.message_num)
	if msgCount > 0 && req.messages != nil {
		cMessages := unsafe.Slice(req.messages, msgCount)
		for i := 0; i < msgCount; i++ {
			cMsg := cMessages[i]
			if cMsg.role == nil || cMsg.content == nil {
				log.Error().Msgf("%v th messages, cMsg content is nil", i)
				return C.AIGW_ERR_INVALID_PARAM
			}
			role := C.GoString(cMsg.role)
			content := C.GoString(cMsg.content)
			if strings.TrimSpace(role) == "" || strings.TrimSpace(content) == "" {
				log.Error().Msgf("%v th messages, role or content is empty", i)
				return C.AIGW_ERR_INVALID_PARAM
			}
			goReq.Messages = append(goReq.Messages, base.OpenAiMessage{
				Role:    role,
				Content: content,
			})
		}
	} else {
		log.Error().Msgf("req message_num or messages is empty.")
		return C.AIGW_ERR_INVALID_PARAM
	}
	// Convert aigw_select_context_t to RegisterInstanceMsg.
	goCtx := server.RegMsgCtx{}
	nodeCount := int(ctx.node_num)
	if nodeCount > 0 && ctx.node_list != nil {
		cNodes := unsafe.Slice(ctx.node_list, nodeCount)
		for i := 0; i < nodeCount; i++ {
			cNode := cNodes[i]
			if cNode.node_addr == nil || cNode.group_id == nil {
				log.Error().Msgf("%v th node, node_addr or group_id failed", i)
				return C.AIGW_ERR_INVALID_PARAM
			}
			name := C.GoString(cNode.node_addr)
			if strings.TrimSpace(name) == "" {
				log.Error().Msgf("%v th node, node_addr failed", i)
				return C.AIGW_ERR_INVALID_PARAM
			}
			host, portStr, err := net.SplitHostPort(name)
			if err != nil {
				log.Error().Msgf("%v th node, node_addr SplitHostPort ip and port err:%v", i, err)
				return C.AIGW_ERR_INVALID_PARAM
			}

			roleStr, ok := roleMap[int(cNode.role)]
			if !ok {
				log.Error().Msgf("%v th node, role:%v failed to map to roleMap", i, int(cNode.role))
				return C.AIGW_ERR_INVALID_PARAM
			}

			group_id := C.GoString(cNode.group_id)
			if strings.TrimSpace(group_id) == "" {
				log.Error().Msgf("%v th node, group_id is empty", i)
				return C.AIGW_ERR_INVALID_PARAM
			}

			goCtx.RegInstanceMsg = append(goCtx.RegInstanceMsg, &gs.RegisterInstanceMsg{
				Name:    name,
				IP:      host,
				Port:    portStr,
				Role:    roleStr,
				GroupID: group_id,
			})
		}
	} else {
		log.Error().Msgf("ctx node_num or node_list is empty.")
		return C.AIGW_ERR_INVALID_PARAM
	}

	result, err := server.SelectWithContext(&goReq, &goCtx)
	if err != nil {
		str2Char(out_result.error_desc[:], err.Error(), int(C.AIGW_ERR_DESC_MAX_LEN))
		return go2cError(err)
	}
	if result == nil || result.TargetPrefillUrl == "" {
		str2Char(out_result.error_desc[:], "no suitable node", int(C.AIGW_ERR_DESC_MAX_LEN))
		return C.AIGW_ERR_NOT_FOUND
	}

	str2Char(out_result.prefill_node_addr[:], result.TargetPrefillUrl,
		int(C.AIGW_ADDR_MAX_LEN))
	str2Char(out_result.decode_node_addr[:], result.TargetDecodeUrl,
		int(C.AIGW_ADDR_MAX_LEN))

	return C.AIGW_SUCCESS
}

//export aigw_notify_event
func aigw_notify_event(event_type C.aigw_event_type_t,
	event *C.aigw_event_info_t) C.aigw_error_t {
	if err := aigw_check_state(); err != C.AIGW_SUCCESS {
		return err
	}

	if event == nil || event.model == nil || event.request_id == nil || event.event_name == nil {
		log.Error().Msgf("ERR: The event parameter passed is empty.")
		return C.AIGW_ERR_INVALID_PARAM
	}

	switch event_type {
	case C.AIGW_EVENT_REQUEST:
		reqEvent := server.RequestEvent{}
		model := C.GoString(event.model)
		id := C.GoString(event.request_id)
		desc := C.GoString(event.event_name)
		if strings.TrimSpace(model) == "" || strings.TrimSpace(id) == "" ||
			strings.TrimSpace(desc) == "" {
			log.Error().Msgf("The model, id , event_name parameter is incorrect, one of them is empty.")
			return C.AIGW_ERR_INVALID_PARAM
		}
		reqEvent.Model = model
		reqEvent.ID = id
		reqEvent.EventDesc = desc
		if err := server.NotifyEvent(&reqEvent); err != nil {
			log.Error().Msgf("ERR: NotifyEvent failed:%v.", err)
			return go2cError(err)
		}
	default:
		log.Error().Msgf("[Event] Unknown event type.")
		return C.AIGW_ERR_INVALID_PARAM
	}

	return C.AIGW_SUCCESS
}

//export aigw_register_cache_driver
func aigw_register_cache_driver(driver *C.aigw_cache_driver_t) C.aigw_error_t {
	if !server.IsInitComp() {
		fmt.Printf("ERR: The AIGW library is not initialized.\n")
		return C.AIGW_ERR_COMP_NOT_INIT
	}

	if driver == nil || driver.driver_name == nil {
		log.Error().Msgf("The driver or name parameter passed is empty.")
		return C.AIGW_ERR_INVALID_PARAM
	}

	if C.check_driver_ops(&driver.ops) != C.AIGW_SUCCESS {
		log.Error().Msgf("The cache driver ops is invalid.")
		return C.AIGW_ERR_INVALID_PARAM
	}

	if server.IsRegCacheDriver() {
		log.Error().Msgf("Do not register cache driver again.")
		return C.AIGW_ERR_INVALID_STATE
	}

	name := C.GoString(driver.driver_name)
	if strings.TrimSpace(name) == "" {
		log.Error().Msgf("The name parameter is incorrect.")
		return C.AIGW_ERR_INVALID_PARAM
	}

	C.save_driver_ops(driver.ops)
	server.RegisterCacheDriverOps(name, &cachecenter.CacheDriverOps{
		HGetAll:      GoHashGetAll,
		HSet:         GoHashSetFields,
		HDel:         GoHashDeleteFields,
		HGetAllBatch: GoHashGetAllBatch,
	})
	return C.AIGW_SUCCESS
}

// GoHashGetAllBatch gets data multiple hash keys in for batch
func GoHashGetAllBatch(keys []string) ([]map[string]string, error) {
	if len(keys) == 0 {
		return nil, base.AIGW_ERR_INVALID_PARAM
	}

	cKeys := make([]*C.char, len(keys))
	for i, key := range keys {
		cKeys[i] = C.CString(key)
	}
	defer func() {
		for _, ck := range cKeys {
			C.free(unsafe.Pointer(ck))
		}
	}()

	cKeysPtr := &cKeys[0]
	arrayCount := len(keys)
	outArrays := (*C.key_value_array_t)(C.malloc(C.size_t(unsafe.Sizeof(C.key_value_array_t{})) * C.size_t(arrayCount)))
	if outArrays == nil {
		return nil, base.AIGW_ERR_NO_MEMORY
	}
	defer C.free(unsafe.Pointer(outArrays))

	cErr := C.call_hash_get_all_batch(
		(**C.char)(unsafe.Pointer(cKeysPtr)),
		C.uint32_t(len(keys)),
		outArrays,
	)

	result := make([]map[string]string, 0, arrayCount)
	if cErr != C.AIGW_SUCCESS {
		return result, c2goError(cErr)
	}

	arraySlice := unsafe.Slice(outArrays, int(arrayCount))
	for i := 0; i < int(arrayCount); i++ {
		outMap := make(map[string]string, int(arraySlice[i].count))
		if arraySlice[i].count > 0 && arraySlice[i].pairs != nil {
			pairSlice := unsafe.Slice(arraySlice[i].pairs, int(arraySlice[i].count))
			for j := 0; j < int(arraySlice[i].count); j++ {
				pair := pairSlice[j]
				k := C.GoString(&pair.key[0])
				v := C.GoString(&pair.value[0])
				outMap[k] = v
			}
		}
		if arraySlice[i].pairs != nil {
			C.free(unsafe.Pointer(arraySlice[i].pairs))
		}
		result = append(result, outMap)
	}

	return result, c2goError(cErr)
}

// GoHashGetAll gets all data for a single hash key
func GoHashGetAll(key string) (map[string]string, error) {
	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))

	var outMap C.key_value_array_t

	cErr := C.call_hash_get_all(cKey, &outMap)
	defer C.free(unsafe.Pointer(outMap.pairs))
	result := make(map[string]string, int(outMap.count))
	if cErr == C.AIGW_SUCCESS && outMap.count > 0 {
		pairs := unsafe.Slice(outMap.pairs, int(outMap.count))
		for i := 0; i < int(outMap.count); i++ {
			pair := pairs[i]
			k := C.GoString(&pair.key[0])
			v := C.GoString(&pair.value[0])
			result[k] = v
		}
	}
	return result, c2goError(cErr)
}

// GoHashSetFields is go hash set faileds
func GoHashSetFields(key string, fields map[string]string, ttl int) error {
	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))

	count := len(fields)
	if count == 0 {
		return base.AIGW_ERR_INVALID_PARAM
	}

	size := C.size_t(C.sizeof_key_value_pair_t * count)
	cPairs := (*C.key_value_pair_t)(C.malloc(size))
	if cPairs == nil {
		return base.AIGW_ERR_NO_MEMORY
	}
	defer C.free(unsafe.Pointer(cPairs))

	i := 0
	for k, v := range fields {
		pair := (*C.key_value_pair_t)(unsafe.Pointer(
			uintptr(unsafe.Pointer(cPairs)) + uintptr(i)*C.sizeof_key_value_pair_t,
		))
		i++

		str2Char(pair.key[:], k, int(C.AIGW_CACHE_KEY_MAX_LEN))
		str2Char(pair.value[:], v, int(C.AIGW_CACHE_VALUE_MAX_LEN))
	}

	var cFields C.key_value_array_t
	cFields.pairs = cPairs
	cFields.count = C.int(count)
	cFields.ttl = C.int32_t(ttl)

	cErr := C.call_hash_set_fields(cKey, &cFields)
	return c2goError(cErr)
}

// GoHashDeleteFields is go hash delete failed
func GoHashDeleteFields(key string, fields ...string) error {
	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))

	count := len(fields)
	if count == 0 {
		return base.AIGW_ERR_INVALID_PARAM
	}

	cFieldKeys := (**C.char)(C.malloc(C.size_t(unsafe.Sizeof((*C.char)(nil))) * C.size_t(count)))
	if cFieldKeys == nil {
		return base.AIGW_ERR_NO_MEMORY
	}
	defer C.free(unsafe.Pointer(cFieldKeys))

	cFields := unsafe.Slice(cFieldKeys, count)
	for i, field := range fields {
		cFields[i] = C.CString(field)
	}

	defer func() {
		for i := 0; i < count; i++ {
			if cFields[i] != nil {
				C.free(unsafe.Pointer(cFields[i]))
			}
		}
	}()

	cErr := C.call_hash_delete_fields(cKey, cFieldKeys, C.int(count))
	return c2goError(cErr)
}

//export aigw_unregister_cache_driver
func aigw_unregister_cache_driver() C.aigw_error_t {
	if err := aigw_check_state(); err != C.AIGW_SUCCESS {
		return err
	}

	server.DeleteDriverOps()
	return C.AIGW_SUCCESS
}

//export aigw_register_model
func aigw_register_model(cfg *C.aigw_model_config_t) C.aigw_error_t {
	if err := aigw_check_state(); err != C.AIGW_SUCCESS {
		return err
	}
	if cfg == nil {
		log.Error().Msgf("Failed to register model, the config is empty.")
		return C.AIGW_ERR_INVALID_PARAM
	}

	if cfg.tokenization_ratio < 0.0 {
		log.Error().Msgf("tokenization_ratio %v < 0, it is incorrect", cfg.tokenization_ratio)
		return C.AIGW_ERR_INVALID_PARAM
	}

	config := core.NewDefaultGsConfig(C.GoString(cfg.model))
	config.LoadBalancer.PretrainTTFTPath = C.GoString(cfg.pretrain_ttft_path)
	if cfg.deploy_policy == C.AIGW_DEPLOY_SEPARATED {
		if cfg.p_lb_type == 0 {
			log.Error().Msgf("p_lb_type can not be 0 at separated mode")
			return C.AIGW_ERR_INVALID_PARAM
		}
		config.DeployPolicy = "separated"
		config.LoadBalancer.Prefill = lbTypeMap[int(cfg.p_lb_type)]
		config.LoadBalancer.Decode = lbTypeMap[int(cfg.d_lb_type)]
	} else {
		return C.AIGW_ERR_INVALID_PARAM
	}

	if cfg.cache_refresh_interval_ms > 0 {
		config.CacheRefreshIntervalMs = uint32(cfg.cache_refresh_interval_ms)
	}

	if err := server.RegisterModel(config); err != nil {
		log.Error().Msgf("Failed to register model with error %v", err)
		return C.AIGW_ERR_INTERNAL
	}
	log.Info().
		Str("model", C.GoString(cfg.model)).
		Int("deploy_policy", int(cfg.deploy_policy)).
		Int("prefill_lb_type", int(cfg.p_lb_type)).
		Int("decode_lb_type", int(cfg.d_lb_type)).
		Str("pretrain_ttft_path", C.GoString(cfg.pretrain_ttft_path)).
		Uint32("cache_refresh_interval_ms", uint32(cfg.cache_refresh_interval_ms)).
		Float64("tokenization_ratio", float64(cfg.tokenization_ratio)).
		Msg("Register model success")
	return C.AIGW_SUCCESS
}

//export aigw_unregister_model
func aigw_unregister_model(model_name *C.char) C.aigw_error_t {
	if err := aigw_check_state(); err != C.AIGW_SUCCESS {
		return err
	}
	if model_name == nil {
		return C.AIGW_ERR_INVALID_PARAM
	}

	model := C.GoString(model_name)
	err := server.UnregisterModel(model)
	if err != nil {
		log.Error().Msgf("Failed to unregister model %v with err %v.", model, err)
		return C.AIGW_ERR_INTERNAL
	}
	log.Info().Msgf("Unregister model %v success.", model)
	return C.AIGW_SUCCESS
}

func main() {
	fmt.Println("AIGW Go library loaded")
}
