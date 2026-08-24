/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"huawei.com/aigw/pkg/log"
)

// agentRegister handles POST /aigw/v1/agents/register.
func (s *HttpServer) agentRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		AgentID  string            `json:"agent_id"`
		Models   []string          `json:"models"`
		Metadata map[string]string `json:"metadata,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.AgentID == "" {
		http.Error(w, "agent_id required", http.StatusBadRequest)
		return
	}
	reg := s.manager.GetAgentRegistry()
	if reg == nil {
		http.Error(w, "kvc disabled", http.StatusServiceUnavailable)
		return
	}
	if err := reg.Register(req.AgentID, req.Models, req.Metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Info().Str("agent_id", req.AgentID).Msg("[kvc] agent registered")
	w.WriteHeader(http.StatusCreated)
}

// agentRoute is the catch-all sub-router for /aigw/v1/agents/{id}/* paths.
// ServeMux has no path-param matching, so we dispatch by inspecting r.URL.Path.
// Paths: /aigw/v1/agents/{id}/heartbeat|recover|unregister,
//
//	/aigw/v1/agents/{id}/sessions/{sid}/close
func (s *HttpServer) agentRoute(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/aigw/v1/agents/")
	// strip a single trailing slash so /agents/{id}/ and /agents/{id} route the same.
	rest = strings.TrimSuffix(rest, "/")
	parts := strings.Split(rest, "/")
	if len(parts) < 1 || parts[0] == "" {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	agentID := parts[0]
	switch {
	case len(parts) == 1:
		// GET /aigw/v1/agents/{id} — agent detail (debug)
		s.agentDetail(w, r, agentID)
	case len(parts) == 2 && parts[1] == "heartbeat":
		s.agentHeartbeat(w, r, agentID)
	case len(parts) == 2 && parts[1] == "recover":
		s.agentRecover(w, r, agentID)
	case len(parts) == 2 && parts[1] == "unregister":
		s.agentUnregister(w, r, agentID)
	case len(parts) == 4 && parts[1] == "sessions" && parts[3] == "close":
		s.sessionClose(w, r, agentID, parts[2])
	default:
		http.Error(w, "bad path", http.StatusBadRequest)
	}
}

func (s *HttpServer) agentHeartbeat(w http.ResponseWriter, r *http.Request, agentID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Models     []string `json:"models"`
		SessionIDs []string `json:"session_ids,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	reg := s.manager.GetAgentRegistry()
	if reg == nil {
		http.Error(w, "kvc disabled", http.StatusServiceUnavailable)
		return
	}
	if err := reg.Heartbeat(agentID, req.Models, req.SessionIDs); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *HttpServer) agentRecover(w http.ResponseWriter, r *http.Request, agentID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Models []string `json:"models"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	reg := s.manager.GetAgentRegistry()
	if reg == nil {
		http.Error(w, "kvc disabled", http.StatusServiceUnavailable)
		return
	}
	if err := reg.Recover(agentID, req.Models); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *HttpServer) agentUnregister(w http.ResponseWriter, r *http.Request, agentID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	reg := s.manager.GetAgentRegistry()
	if reg == nil {
		http.Error(w, "kvc disabled", http.StatusServiceUnavailable)
		return
	}
	if err := reg.Unregister(agentID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *HttpServer) sessionClose(w http.ResponseWriter, r *http.Request, agentID, sessionID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = agentID // session-close is session-scoped; CloseSession iterates all GS managers.
	if err := s.manager.CloseSession(sessionID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Info().Str("agent_id", agentID).Str("session_id", sessionID).Msg("[kvc] session closed")
	w.WriteHeader(http.StatusOK)
}

// agentsList handles GET /aigw/v1/agents (debug: list all registered agents).
func (s *HttpServer) agentsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	reg := s.manager.GetAgentRegistry()
	if reg == nil {
		http.Error(w, "kvc disabled", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, reg.All())
}

// agentDetail handles GET /aigw/v1/agents/{id} (debug: one agent's state).
func (s *HttpServer) agentDetail(w http.ResponseWriter, r *http.Request, agentID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	reg := s.manager.GetAgentRegistry()
	if reg == nil {
		http.Error(w, "kvc disabled", http.StatusServiceUnavailable)
		return
	}
	a, ok := reg.Get(agentID)
	if !ok {
		http.Error(w, "agent not found", http.StatusNotFound)
		return
	}
	writeJSON(w, a)
}

// sessionDetail handles GET /aigw/v1/models/{m}/kvc/sessions/{sid} (debug: one session).
func (s *HttpServer) sessionDetail(w http.ResponseWriter, r *http.Request, model, sessionID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	g := s.manager.GetGsManagerByModel(model)
	if g == nil {
		http.Error(w, "model not found", http.StatusNotFound)
		return
	}
	kvc := g.GetKvcSessionManager()
	if kvc == nil {
		http.Error(w, "kvc disabled for model", http.StatusServiceUnavailable)
		return
	}
	sess, ok := kvc.GetSession(sessionID)
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	writeJSON(w, sess)
}

// blockDetail handles GET /aigw/v1/models/{m}/kvc/blocks/{h} (debug: one block).
func (s *HttpServer) blockDetail(w http.ResponseWriter, r *http.Request, model string, hash int64) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	g := s.manager.GetGsManagerByModel(model)
	if g == nil {
		http.Error(w, "model not found", http.StatusNotFound)
		return
	}
	kvc := g.GetKvcSessionManager()
	if kvc == nil {
		http.Error(w, "kvc disabled for model", http.StatusServiceUnavailable)
		return
	}
	bi := kvc.GetBlock(hash)
	if bi == nil {
		http.Error(w, "block not found", http.StatusNotFound)
		return
	}
	writeJSON(w, bi)
}

// modelKvcRoute dispatches GET /aigw/v1/models/{m}/kvc/sessions/{sid} and
// /aigw/v1/models/{m}/kvc/blocks/{h} (debug endpoints).
func (s *HttpServer) modelKvcRoute(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/aigw/v1/models/")
	parts := strings.Split(rest, "/")
	// parts: {m}/kvc/sessions/{sid}  OR  {m}/kvc/blocks/{h}
	if len(parts) != 4 || parts[1] != "kvc" {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	model := parts[0]
	switch parts[2] {
	case "sessions":
		s.sessionDetail(w, r, model, parts[3])
	case "blocks":
		hash, err := strconv.ParseInt(parts[3], 10, 64)
		if err != nil {
			http.Error(w, "bad block hash", http.StatusBadRequest)
			return
		}
		s.blockDetail(w, r, model, hash)
	default:
		http.Error(w, "bad path", http.StatusBadRequest)
	}
}

// writeJSON marshals v as JSON and writes it with a 200 response.
func writeJSON(w http.ResponseWriter, v interface{}) {
	jsonData, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err = w.Write(jsonData); err != nil {
		log.Warn().Msgf("[kvc] error writing debug response: %v", err)
	}
}
