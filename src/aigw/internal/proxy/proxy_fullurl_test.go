/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// internal/proxy/proxy_fullurl_test.go
package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestForwardRequest_UsesFullURL(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	pm := NewProxyManager(context.Background(), nil)
	defer pm.Stop()

	res, err := pm.ForwardRequest(context.Background(), &ForwardRequest{
		Method:  "POST",
		FullURL: srv.URL + "/v1/chat/completions",
		Headers: http.Header{},
		Body:    []byte(`{"model":"x"}`),
	})
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "/v1/chat/completions", gotPath)
}

func TestForwardRequest_FallsBackToTargetURLPlusRoute(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pm := NewProxyManager(context.Background(), nil)
	defer pm.Stop()

	_, err := pm.ForwardRequest(context.Background(), &ForwardRequest{
		Method:    "POST",
		TargetURL: srv.URL,
		Route:     "/v1/chat/completions",
		Headers:   http.Header{},
		Body:      []byte(`{}`),
	})
	assert.NoError(t, err)
	assert.Equal(t, "/v1/chat/completions", gotPath)
}
