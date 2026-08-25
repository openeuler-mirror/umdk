/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package gs

// kvcSubscriberAdapter bridges agentregistry.Subscriber events into KvcSessionManager
// strategy invocations. On OnAgentSuspected it runs OffloadStrategy.Plan and dispatches
// the resulting hint; on OnAgentRecovered it prefetches; on OnAgentGone it marks sessions
// Terminated; on OnAgentUnregistered it immediately evicts.
type kvcSubscriberAdapter struct {
	mgr *KvcSessionManager
}

func (a *kvcSubscriberAdapter) OnAgentActive(agentID string, _ []string) {
	// no action (design §2 event table)
	_ = agentID
}
func (a *kvcSubscriberAdapter) OnAgentSuspected(agentID string) {
	ctx := OffloadContext{AgentID: agentID, Model: a.mgr.modelName, Reason: "agent_suspected"}
	if _, err := a.mgr.planAndDispatchOffload(ctx); err != nil {
		// logged inside planAndDispatch; alarm handled in F1
	}
}
func (a *kvcSubscriberAdapter) OnAgentRecovered(agentID string, _ []string) {
	ctx := PrefetchContext{AgentID: agentID, Model: a.mgr.modelName, Reason: "agent_recovered"}
	_, _ = a.mgr.planAndDispatchPrefetch(ctx)
}
func (a *kvcSubscriberAdapter) OnAgentGone(agentID string) {
	// mark sessions Terminated; aging loop evicts after grace (Task F3)
	a.mgr.terminateSessions(agentID)
}
func (a *kvcSubscriberAdapter) OnAgentUnregistered(agentID string) {
	// immediate evict (design §5 "Decision matrix")
	_ = a.mgr.evictAgentSessions(agentID)
}
