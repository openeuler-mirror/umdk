/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package stats

import "testing"

func TestKvcStatsRecord(t *testing.T) {
	s := NewDataPlaneStats()
	s.Record(StatAgentSuspected)
	s.Record(StatAgentSuspected)
	s.Record(StatHintsIssuedOffload)
	m := s.GetStatsMap()
	if m["StatAgentSuspected"] != 2 {
		t.Fatalf("StatAgentSuspected=%d want 2", m["StatAgentSuspected"])
	}
	if m["StatHintsIssuedOffload"] != 1 {
		t.Fatalf("StatHintsIssuedOffload=%d want 1", m["StatHintsIssuedOffload"])
	}
}
