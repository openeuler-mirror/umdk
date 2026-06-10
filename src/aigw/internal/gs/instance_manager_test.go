/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: dispatching schedule request.
 * Create: 2025-05-13
 */

// Package gs is the global scheduler for gateway.
package gs

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/cachecenter"

	"github.com/agiledragon/gomonkey/v2"
)

func TestAddInstance(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insConnectType = "sse"
	patchIns := gomonkey.ApplyPrivateMethod(insManager, "startIns", func() bool { return true })
	defer patchIns.Reset()

	// add ins
	insUrl := "localhost:8888"
	insRole := base.MixedRoleInstance
	statusChan := make(chan *ControlMessage, 1)
	err := insManager.addInstance(insUrl, insRole, "test_id", statusChan)
	if err != nil {
		t.Errorf("Failed to add instance: %s", insUrl)
	}
	newIns, exists := insManager.insPool[insUrl]
	if !exists {
		t.Errorf("Instance %s not found in pool after adding", insUrl)
	}

	assert.Equal(t, newIns.insUrl, insUrl)
	assert.Equal(t, newIns.insRole, insRole)
	assert.Equal(t, newIns.groupID, "test_id")
	assert.Equal(t, newIns.reqStatusChan, statusChan)

	// add repeat ins
	statusChan2 := make(chan *ControlMessage, 1)
	err = insManager.addInstance(insUrl, insRole, "", statusChan2)
	if err == nil {
		t.Errorf("Successfully added duplicate instance: %s", insUrl)
	}
}

func TestRemoveInstance(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insConnectType = "sse"
	patchIns := gomonkey.ApplyPrivateMethod(insManager, "startIns", func() bool { return true })
	defer patchIns.Reset()
	// add ins
	insUrl := "localhost:8888"
	insRole := base.MixedRoleInstance
	statusChan := make(chan *ControlMessage, 1)
	err := insManager.addInstance(insUrl, insRole, "", statusChan)
	if err != nil {
		t.Errorf("Failed to add instance: %s", insUrl)
	}
	// remove exits ins
	success := insManager.removeInstance(insUrl)
	if !success {
		t.Errorf("Failed to remove instance: %s", insUrl)
	}
	if _, exists := insManager.insPool[insUrl]; exists {
		t.Errorf("Instance %s still exists in pool after removal", insUrl)
	}

	// remove not exits ins
	success = insManager.removeInstance("http://nonexistent")
	if success {
		t.Error("Successfully removed non-existent instance")
	}
}

func TestUpdatePoolShot(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insConnectType = "sse"
	patchIns := gomonkey.ApplyPrivateMethod(insManager, "startIns", func() bool { return true })
	defer patchIns.Reset()

	insUrl := "localhost:8888"
	insRole := base.MixedRoleInstance
	statusChan := make(chan *ControlMessage, 1)
	insManager.addInstance(insUrl, insRole, "", statusChan)
	insManager.insPool[insUrl].insWatcher.setHealth()
	insManager.updatePoolShot()
	insManager.snapshotRWLock.Lock()
	defer insManager.snapshotRWLock.Unlock()
	if len(insManager.insSnapshots) != 1 {
		t.Error("No snapshots updated after calling updatePoolShot")
	}
}

func TestSnapShotLoop(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insConnectType = "sse"
	patchIns := gomonkey.ApplyPrivateMethod(insManager, "startIns", func() bool { return true })
	defer patchIns.Reset()

	insUrl := "localhost:8888"
	insRole := base.MixedRoleInstance
	statusChan := make(chan *ControlMessage, 1)
	insManager.addInstance(insUrl, insRole, "", statusChan)
	insManager.insPool[insUrl].insWatcher.setHealth()

	insManager.start()
	time.Sleep(insSnapShotFreq)
	time.Sleep(insSnapShotFreq)

	insManager.snapshotRWLock.Lock()
	defer insManager.snapshotRWLock.Unlock()
	if len(insManager.insSnapshots) != 1 {
		t.Error("No snapshots updated after starting snapShotLoop")
	}
}

func TestAddReqToManager(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insConnectType = "sse"
	patchIns := gomonkey.ApplyPrivateMethod(insManager, "startIns", func() bool { return true })
	defer patchIns.Reset()

	insUrl := "localhost:8888"
	insRole := base.MixedRoleInstance
	statusChan := make(chan *ControlMessage, 1)
	insManager.addInstance(insUrl, insRole, "", statusChan)

	reqId := "test"
	req := &LlmRequest{
		ReqId: reqId,
	}

	insManager.addReq(insUrl, req)
	time.Sleep(1 * time.Second)
	insManager.poolRWLock.RLock()
	defer insManager.poolRWLock.RUnlock()
	ins := insManager.insPool[insUrl]
	ins.rwLock.RLock()
	defer ins.rwLock.RUnlock()
	if _, exists := ins.reqSet[reqId]; !exists {
		t.Errorf("add req into insManager failed,%+v", ins)
	}
}

func TestStartStop(t *testing.T) {
	insManager := newInstanceManager()
	insManager.insConnectType = "sse"
	done := make(chan int)
	go func() {
		insManager.start()
		insManager.stop()
		close(done)
	}()

	select {
	case <-done:
		return
	case <-time.After(1 * time.Second):
		t.Error("insManager quit err, timeout")
	}
}

func TestUpdateEmaPredictLen(t *testing.T) {
	insMgr := newInstanceManager()
	insMgr.insConnectType = "sse"
	t.Logf("Running test for updateEmaPredictionLen")
	// test the case where there is no historical decode length
	insMgr.updateEmaPredictLen(ReqTypeUltraShort, 200)
	if insMgr.emaPredictLen[ReqTypeUltraShort] != 200 {
		t.Errorf("predictLen expect 200, go %d", insMgr.emaPredictLen[ReqTypeUltraShort])
	}

	// test the case where this exists historical decode length
	insMgr.updateEmaPredictLen(ReqTypeUltraShort, 20)
	if insMgr.emaPredictLen[ReqTypeUltraShort] != 38 {
		t.Errorf("predictLen expect 38, got %d", insMgr.emaPredictLen[ReqTypeUltraShort])
	}
}

func TestPredictTokenLen(t *testing.T) {
	insMgr := newInstanceManager()
	insMgr.insConnectType = "sse"
	t.Logf("Running test for PredictTokenLen")
	req1 := &LlmRequest{
		ReqId:     "test",
		ReqType:   ReqTypeMiddle,
		PromptLen: 800,
	}
	// test for non-existent request type
	predictLen := insMgr.predictTokensByEMA(req1)
	if predictLen != 800 {
		t.Errorf("predictLen expect 800, got %d", predictLen)
	}

	// test for existent request type
	req2 := &LlmRequest{
		ReqId:     "test",
		ReqType:   ReqTypeMiddle,
		PromptLen: 500,
	}
	insMgr.emaPredictLen[ReqTypeMiddle] = 1000
	predictLen = insMgr.predictTokensByEMA(req2)
	if predictLen != 1500 {
		t.Errorf("predictLen expect 1500, got %d", predictLen)
	}
}

func TestLoadInsFromCache(t *testing.T) {
	insManager := newInstanceManager()
	cacheManager := &cachecenter.CacheManager{}
	insManager.cacheManager = cacheManager

	instances := []*RegisterInstanceMsg{
		&RegisterInstanceMsg{
			Name:    "instance1",
			Model:   "qwen",
			IP:      "192.168.0.1",
			Port:    "8888",
			Role:    "mixed",
			GroupID: "group1",
		},
		&RegisterInstanceMsg{
			Name:    "instance2",
			Model:   "qwen",
			IP:      "192.168.0.2",
			Port:    "8888",
			Role:    "mixed",
			GroupID: "group2",
		},
		&RegisterInstanceMsg{
			Name:    "instance3",
			Model:   "qwen",
			IP:      "192.168.0.3",
			Port:    "8888",
			Role:    "mixed",
			GroupID: "group1",
		},
	}

	ins1Id := base.BuildInstanceAddress("192.168.0.1", "8888", 0)
	ins2Id := base.BuildInstanceAddress("192.168.0.2", "8888", 0)
	ins3Id := base.BuildInstanceAddress("192.168.0.3", "8888", 0)

	// mock RangeMetrics, metric cache contain ins1 ins3, not contain ins2
	patches := gomonkey.ApplyMethod(reflect.TypeOf(cacheManager), "RangeMetrics",
		func(_ *cachecenter.CacheManager, f func(string, *cachecenter.InstanceMetrics) bool) {
			metricsData := map[string]*cachecenter.InstanceMetrics{
				ins1Id: {
					TokenLoad: 100,
					QueueTime: 50.0,
					HeadReq: &cachecenter.RequestInfo{
						ReqId:              "req1",
						PredictPrefillTime: 10.0,
						PrefillStartTimeMs: 1000,
					},
				},
				ins3Id: {
					TokenLoad: 200,
					QueueTime: 75.0,
					HeadReq: &cachecenter.RequestInfo{
						ReqId:              "req2",
						PredictPrefillTime: 15.0,
						PrefillStartTimeMs: 2000,
					},
				},
			}

			for instanceId, metric := range metricsData {
				if !f(instanceId, metric) {
					break
				}
			}
		})
	defer patches.Reset()

	insManager.loadInsFromCache(instances)

	assert.Equal(t, 3, len(insManager.insPool), "should be 3 instance")

	ins1, exists := insManager.insPool[ins1Id]
	assert.True(t, exists, "instance1 should exists")
	if exists {
		assert.Equal(t, ins1Id, ins1.insUrl)
		assert.Equal(t, "group1", ins1.groupID)
		assert.Equal(t, base.MixedRoleInstance, ins1.insRole)
		assert.Equal(t, 100, ins1.tokenNum)
		assert.Equal(t, 50.0, ins1.prefillTime)
	}

	ins2, exists := insManager.insPool[ins2Id]
	assert.True(t, exists, "instance2 should exists")
	if exists {
		assert.Equal(t, ins2Id, ins2.insUrl)
		assert.Equal(t, "group2", ins2.groupID)
		assert.Equal(t, base.MixedRoleInstance, ins2.insRole)
		assert.Equal(t, 0, ins2.tokenNum)
		assert.Equal(t, 0.0, ins2.prefillTime)
	}

	ins3, exists := insManager.insPool[ins3Id]
	assert.True(t, exists, "instance3 should exists")
	if exists {
		assert.Equal(t, ins3Id, ins3.insUrl)
		assert.Equal(t, "group1", ins3.groupID)
		assert.Equal(t, base.MixedRoleInstance, ins3.insRole)
		assert.Equal(t, 200, ins3.tokenNum)
		assert.Equal(t, 75.0, ins3.prefillTime)
	}

	// instanceList contains ins1 ins3, ins2 offline
	instances = []*RegisterInstanceMsg{
		&RegisterInstanceMsg{
			Name:    "instance1",
			Model:   "qwen",
			IP:      "192.168.0.1",
			Port:    "8888",
			Role:    "mixed",
			GroupID: "group1",
		},
		&RegisterInstanceMsg{
			Name:    "instance3",
			Model:   "qwen",
			IP:      "192.168.0.3",
			Port:    "8888",
			Role:    "mixed",
			GroupID: "group1",
		},
	}

	// mock RangeMetrics, metric cache contain ins1 ins2, not contain ins3
	patches2 := gomonkey.ApplyMethod(reflect.TypeOf(cacheManager), "RangeMetrics",
		func(_ *cachecenter.CacheManager, f func(string, *cachecenter.InstanceMetrics) bool) {
			metricsData := map[string]*cachecenter.InstanceMetrics{
				ins1Id: {
					TokenLoad: 100,
					QueueTime: 50.0,
					HeadReq: &cachecenter.RequestInfo{
						ReqId:              "req1",
						PredictPrefillTime: 10.0,
						PrefillStartTimeMs: 1000,
					},
				},
				ins2Id: {
					TokenLoad: 200,
					QueueTime: 75.0,
					HeadReq: &cachecenter.RequestInfo{
						ReqId:              "req2",
						PredictPrefillTime: 15.0,
						PrefillStartTimeMs: 2000,
					},
				},
			}
			for instanceId, metric := range metricsData {
				if !f(instanceId, metric) {
					break
				}
			}
		})
	defer patches2.Reset()

	insManager.loadInsFromCache(instances)

	assert.Equal(t, 2, len(insManager.insPool), "should be 2 instance")

	ins1, exists = insManager.insPool[ins1Id]
	assert.True(t, exists, "instance1 should exists")
	if exists {
		assert.Equal(t, ins1Id, ins1.insUrl)
		assert.Equal(t, "group1", ins1.groupID)
		assert.Equal(t, base.MixedRoleInstance, ins1.insRole)
		assert.Equal(t, 100, ins1.tokenNum)
		assert.Equal(t, 50.0, ins1.prefillTime)
	}

	ins3, exists = insManager.insPool[ins3Id]
	assert.True(t, exists, "instance3 should exists")
	if exists {
		assert.Equal(t, ins3Id, ins3.insUrl)
		assert.Equal(t, "group1", ins3.groupID)
		assert.Equal(t, base.MixedRoleInstance, ins3.insRole)
		assert.Equal(t, 0, ins3.tokenNum)
		assert.Equal(t, 0.0, ins3.prefillTime)
	}

}

func TestLoadInsFromCacheEmptyInstances(t *testing.T) {
	insManager := newInstanceManager()
	cacheManager := &cachecenter.CacheManager{}
	insManager.cacheManager = cacheManager

	var instances []*RegisterInstanceMsg

	patches := gomonkey.ApplyMethod(reflect.TypeOf(cacheManager), "RangeMetrics",
		func(_ *cachecenter.CacheManager, f func(string, *cachecenter.InstanceMetrics) bool) {
			// empty implement
		})
	defer patches.Reset()

	insManager.loadInsFromCache(instances)

	assert.Equal(t, 0, len(insManager.insPool), "insPool should be empty")
}
