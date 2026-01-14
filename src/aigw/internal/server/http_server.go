/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: HttpServer provides HTTP services for AIGW.
 * Create: 2025-05-13
 */

// Package server provides north interfaces for AIGW.
package server

import "C"
import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/core"
	"huawei.com/aigw/pkg/crypto"
	"huawei.com/aigw/pkg/log"
)

const (
	shutDownTimeout        = 3 * time.Second
	waitServerReadyTimeout = 3 * time.Second
	waitServerReadyDelay   = 300 * time.Millisecond
	httpTimeout            = 50 * time.Millisecond
)

var maxConcurrency = 128

// HttpServer provides inference suggestion service.
type HttpServer struct {
	manager *core.AigwManager
	server  *http.Server
	host    string
	port    string

	serHmacMgr *crypto.HmacManager
	serAesMgr  *crypto.AesManager

	isReady bool
	readyMu sync.RWMutex
}

// NewHttpServer creates a new httpServer manager.
func NewHttpServer(manager *core.AigwManager, host string, port string) *HttpServer {
	return &HttpServer{
		manager:    manager,
		host:       host,
		port:       port,
		serHmacMgr: crypto.NewHmacManager(nil),
		serAesMgr:  crypto.NewAesManager(nil),
		isReady:    false,
	}
}

func (s *HttpServer) setReady() {
	s.readyMu.Lock()
	defer s.readyMu.Unlock()
	s.isReady = true

}

func (s *HttpServer) isServerReady() bool {
	s.readyMu.RLock()
	defer s.readyMu.RUnlock()
	return s.isReady
}

// Start the httpServer.
func (s *HttpServer) Start() error {
	reqChan := make(chan struct{}, maxConcurrency)

	// Global Concurrency Limit Middleware
	limiterMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/aigw/v1/health" {
				next.ServeHTTP(w, r)
				return
			}

			if !s.isServerReady() {
				http.Error(w, "Service Not Ready", http.StatusServiceUnavailable)
				return
			}
			select {
			case reqChan <- struct{}{}:
				defer func() { <-reqChan }()
				next.ServeHTTP(w, r) // Proceed to the subsequent middleware or handler
			default:
				msg := fmt.Sprintf("Too many requests; the current number of requests is %v, "+
					"and the maximum number of requests is %v.", maxConcurrency, maxConcurrency)
				log.Error().Msg(msg)
				http.Error(w, msg, http.StatusTooManyRequests)
			}

		})
	}

	mx := http.NewServeMux()
	mx.HandleFunc("/aigw/v1/health", s.health)
	mx.HandleFunc("/aigw/v1/register-instance", s.serHmacMgr.WithHMAC(s.registerInstance))
	mx.HandleFunc("/aigw/v1/unregister-instance", s.serHmacMgr.WithHMAC(s.unregisterInstance))
	mx.HandleFunc("/aigw/v1/openai/get-suggestion",
		s.serHmacMgr.WithHMAC(s.serAesMgr.WithAesDecrypt(s.scheduleForOpenAi)))
	mx.HandleFunc("/aigw/v1/stats", s.serHmacMgr.WithHMAC(s.stats))
	s.server = &http.Server{
		Addr:    net.JoinHostPort(s.host, s.port),
		Handler: limiterMiddleware(mx),
	}

	log.Info().Msgf("HTTP server starting on %v", s.server.Addr)

	errChan := make(chan error, 1)
	go func() {
		var err error
		if err = s.server.ListenAndServe(); err != nil {
			log.Warn().Msgf("server exited abnormally, err: %v", err)
		}
		errChan <- err
	}()

	// Wait for the server to be ready
	return s.checkHealth(errChan)
}

// Stop the httpServer.
func (s *HttpServer) Stop() {
	if s.server == nil {
		return
	}

	log.Info().Msg("shutting down HTTP server")

	ctx, _ := context.WithTimeout(context.Background(), shutDownTimeout)
	if err := s.server.Shutdown(ctx); err != nil {
		log.Warn().Msgf("HTTP server stop failed: %v", err)
		return
	}

	log.Info().Msg("HTTP server shutdown gracefully")
}

// health will check the health of AIGW, return 200 when healthy, else value when not healthy
func (s *HttpServer) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Debug().Msgf("AIGW is health")
	w.WriteHeader(http.StatusOK)
}

// stats will check the statistical counts of the aigw in data plane.
func (s *HttpServer) stats(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	result := s.manager.GetAllStats()
	jsonData, err := json.Marshal(result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if _, err = w.Write(jsonData); err != nil {
		log.Warn().Msgf("Error writing response: %v", err)
	}
}

// registerInstance is the north interface to register new instance for globalScheduler.
// Notice: this function is optional, only used for testing.
func (s *HttpServer) registerInstance(w http.ResponseWriter, r *http.Request) {
	if s.manager.IsEnableZK() {
		err := fmt.Errorf("the zookeeper manager is enable, please use zookeeper to register or unregister")
		http.Error(w, err.Error(), http.StatusForbidden)
		log.Error().Msgf("%v", err)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Body == nil || r.ContentLength == 0 {
		err := fmt.Errorf("the body is None")
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Error().Msgf("failed to decode register instance, err: %v", err)
		return
	}

	var req base.RegisterInstanceIn
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Error().Msgf("failed to decode register instance, err: %v", err)
		return
	}

	log.Info().Msgf("start to register instance %v, model: %v, role: %v", req.Name, req.Model, req.Role)

	if err := s.manager.RegisterInstance(&req); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Error().Msgf("failed to register instance, err: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	log.Info().Msgf("register instance successfully, model: %v, role: %v", req.Model, req.Role)
}

// unregisterInstance is the north interface to unregister instance for globalScheduler.
// Notice: this function is optional, only used for testing.
func (s *HttpServer) unregisterInstance(w http.ResponseWriter, r *http.Request) {
	if s.manager.IsEnableZK() {
		err := fmt.Errorf("the zookeeper manager is enable, please use zookeeper to register or unregister")
		http.Error(w, err.Error(), http.StatusForbidden)
		log.Error().Msgf("%v", err)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Body == nil || r.ContentLength == 0 {
		err := fmt.Errorf("the body is None")
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Error().Msgf("failed to decode unregister instance, err: %v", err)
		return
	}

	var req base.UnregisterInstanceIn
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Error().Msgf("failed to decode unregister instance, err: %v", err)
		return
	}

	log.Info().Msgf("start to unregister instance (%v:%v), model %v", req.IP, req.Port, req.Model)

	if err := s.manager.UnregisterInstance(&req); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Error().Msgf("failed to unregister instance, err: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	log.Info().Msgf("unregister instance (%v:%v) successfully, model %v", req.IP, req.Port, req.Model)
}

func processMessages(messages []base.OpenAiMessage) string {
	prompt := ""
	for _, m := range messages {
		prompt += m.Role + ":" + m.Content + " "
	}
	return prompt
}

// scheduleForOpenAi is the north data plane interface, it is used for giving schedule
// suggestion based on load of instances.
func (s *HttpServer) scheduleForOpenAi(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Body == nil || r.ContentLength == 0 {
		err := fmt.Errorf("the body is None")
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Error().Msgf("failed to get suggestion, err: %v", err)
		return
	}

	var req base.OpenAiRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	prompt := processMessages(req.Messages)
	if prompt == "" {
		log.Error().Msgf("prompt is empty")
		http.Error(w, "prompt is empty", http.StatusBadRequest)
		return
	}

	aigwCfg := serverHandler.cfgMgr.GetAigwConfig()
	if len([]rune(prompt)) > aigwCfg.Limits.MaxPromptRunes {
		log.Error().Msgf("prompt is too long, characters nums: %v", len([]rune(prompt)))
		http.Error(w, "prompt is too long", http.StatusBadRequest)
		return
	}

	log.Debug().Msgf("processing schedule request, UUID: %v, model: %v", req.UUID, req.Model)
	in := &core.GetSuggestionIn{
		UUID:   req.UUID,
		Model:  req.Model,
		Prompt: prompt,
	}

	out, err := s.manager.GetSuggestion(in)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonData, err := json.Marshal(out)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err = w.Write(jsonData); err != nil {
		log.Warn().Msgf("Error writing response: %v", err)
	}
}

func (s *HttpServer) checkHealth(errChan <-chan error) error {
	// Wait for the server to be ready
	ticker := time.NewTicker(waitServerReadyDelay)
	defer ticker.Stop()
	healthUrl := fmt.Sprintf("http://%s/aigw/v1/health", s.server.Addr)
	client := &http.Client{Timeout: waitServerReadyTimeout}
	startTime := time.Now().UTC()
	req, err := http.NewRequest("GET", healthUrl, nil)
	if err != nil {
		log.Error().Msgf("HTTP server failed to start, err: %v", err)
		return err
	}
	if s.serHmacMgr.EnableHmac() {
		err = s.serHmacMgr.AddHmacSign(req, "")
		if err != nil {
			log.Error().Msgf("HTTP server failed to start, err: %v", err)
			return err
		}

	}
	for {
		select {
		case <-ticker.C:
			resp, err := client.Do(req)
			if err != nil {
				log.Error().Msgf("health check error: %v", err.Error())
				return err
			}
			defer resp.Body.Close()

			if err == nil && resp.StatusCode == http.StatusOK {
				log.Info().Msgf("HTTP server is successfully started")
				s.setReady()
				return nil
			}
			// add a timeout to avoid infinite waiting
			if time.Since(startTime) > waitServerReadyTimeout {
				e1 := fmt.Errorf("server did not start within the expected time %v", waitServerReadyTimeout)
				log.Error().Msgf("%v", e1)
				return e1
			}

		case err := <-errChan:
			log.Error().Msgf("HTTP server failed to start, err: %v", err)
			return err
		}
	}
}
