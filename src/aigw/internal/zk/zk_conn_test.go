/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: zk conn test
 * Create: 2025-07-29
 */

// Package zk provides zookeeper management for AIGW.
package zk

import (
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/go-zookeeper/zk"
	"github.com/stretchr/testify/assert"
)

// TestGoZooKeeperConnInvalidConn tests goZooKeeperConn with invalid zk.conn
func TestGoZooKeeperConnInvalidConn(t *testing.T) {
	conn := newGoZooKeeperConn()
	_, err := conn.Connect([]string{"invalid"}, time.Second, net.DialTimeout)
	assert.Error(t, err)

	_, err = conn.Create("/invalid", []byte{}, zk.FlagEphemeral, zk.WorldACL(zk.PermAll))
	assert.Error(t, err)

	err = conn.Delete("/invalid", -1)
	assert.Error(t, err)

	_, _, err = conn.Exists("/invalid")
	assert.Error(t, err)

	_, _, err = conn.Get("/invalid")
	assert.Error(t, err)

	_, _, err = conn.Children("/invalid")
	assert.Error(t, err)

	_, _, err = conn.ChildrenW("/invalid")
	assert.Error(t, err)

	err = conn.AddAuth("/invalid", []byte{})
	assert.Error(t, err)

	conn.Close()
}

// TestGoZooKeeperConn tests goZooKeeperConn
func TestGoZooKeeperConn(t *testing.T) {
	conn := newGoZooKeeperConn()
	gConn, ok := conn.(*goZooKeeperConn)
	assert.True(t, ok)
	gConn.conn = &zk.Conn{}

	_, err := conn.Connect([]string{"invalid"}, time.Second, net.DialTimeout)
	assert.Error(t, err)

	goZkConn := &zk.Conn{}
	patchReg := gomonkey.ApplyMethod(reflect.TypeOf(goZkConn), "Create",
		func(c *zk.Conn, path string, data []byte, flags int32, acl []zk.ACL) (string, error) {
			return "", fmt.Errorf("error")
		})
	_, err = conn.Create("/invalid", []byte{}, zk.FlagEphemeral, zk.WorldACL(zk.PermAll))
	assert.Error(t, err)
	patchReg.Reset()

	patchReg = gomonkey.ApplyMethod(reflect.TypeOf(goZkConn), "Delete",
		func(c *zk.Conn, path string, version int32) error {
			return fmt.Errorf("error")
		})
	err = conn.Delete("/invalid", -1)
	assert.Error(t, err)
	patchReg.Reset()

	patchReg = gomonkey.ApplyMethod(reflect.TypeOf(goZkConn), "Exists",
		func(c *zk.Conn, path string) (bool, *zk.Stat, error) {
			return false, nil, fmt.Errorf("error")
		})
	_, _, err = conn.Exists("/invalid")
	assert.Error(t, err)
	patchReg.Reset()

	patchReg = gomonkey.ApplyMethod(reflect.TypeOf(goZkConn), "Get",
		func(c *zk.Conn, path string) ([]byte, *zk.Stat, error) {
			return []byte{}, nil, fmt.Errorf("error")
		})
	_, _, err = conn.Get("/invalid")
	assert.Error(t, err)
	patchReg.Reset()

	patchReg = gomonkey.ApplyMethod(reflect.TypeOf(goZkConn), "Children",
		func(c *zk.Conn, path string) ([]string, *zk.Stat, error) {
			return []string{}, nil, fmt.Errorf("error")
		})
	_, _, err = conn.Children("/invalid")
	assert.Error(t, err)
	patchReg.Reset()

	patchReg = gomonkey.ApplyMethod(reflect.TypeOf(goZkConn), "ChildrenW",
		func(c *zk.Conn, path string) ([]string, *zk.Stat, <-chan zk.Event, error) {
			return []string{}, nil, nil, fmt.Errorf("error")
		})
	_, _, err = conn.ChildrenW("/invalid")
	assert.Error(t, err)
	patchReg.Reset()

	patchReg = gomonkey.ApplyMethod(reflect.TypeOf(goZkConn), "AddAuth",
		func(c *zk.Conn, scheme string, auth []byte) error {
			return fmt.Errorf("error")
		})
	err = conn.AddAuth("/invalid", []byte{})
	assert.Error(t, err)
	patchReg.Reset()

	patchReg = gomonkey.ApplyMethod(reflect.TypeOf(goZkConn), "Close", func(c *zk.Conn) {})
	conn.Close()
	patchReg.Reset()
}
