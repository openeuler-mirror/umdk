/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: ZooKeeper connection management
 * Create: 2025-07-21
 */

// Package zk provides zookeeper management for AIGW.
package zk

import (
	"fmt"
	"time"

	"github.com/go-zookeeper/zk"

	"huawei.com/aigw/pkg/log"
)

// ConnOption represents a ZooKeeper connection option.
// It is a function that takes a Connection and modifies its behavior.
type ConnOption func(c Connection)

// Connection is the wrapper for Zookeeper connection management.
// It defines the methods for interacting with a Zookeeper server.
type Connection interface {
	// Connect establishes a connection to the Zookeeper servers.
	// It takes a list of server addresses, a session timeout duration, a dialer, and optional connection options.
	// It returns a channel for receiving Zookeeper events, and an error if the connection fails.
	Connect(servers []string, sessionTimeout time.Duration, dialer zk.Dialer,
		opts ...ConnOption) (<-chan zk.Event, error)

	// Close closes the Zookeeper connection.
	// It should be called to release resources when the connection is no longer needed.
	Close()

	// Create creates a new node in the Zookeeper hierarchy.
	// It takes the path of the node, the data to be stored in the node, flags for node type (e.g., ephemeral),
	// and ACL (Access Control List) for permissions.
	// It returns the path of the created node and an error if the creation fails.
	Create(path string, data []byte, flags int32, acl []zk.ACL) (string, error)

	// Delete deletes an existing node in the Zookeeper hierarchy.
	// It takes the path of the node and the version of the node to delete.
	// It returns an error if the deletion fails.
	Delete(path string, version int32) error

	// Exists checks if a node exists in the Zookeeper hierarchy.
	// It takes the path of the node and returns a boolean indicating whether the node exists,
	// the node's stat information, and an error if the check fails.
	Exists(path string) (bool, *zk.Stat, error)

	// Get retrieves the data and stat information of a node in the Zookeeper hierarchy.
	// It takes the path of the node and returns the data stored in the node, the node's stat information,
	// and an error if the retrieval fails.
	Get(path string) ([]byte, *zk.Stat, error)

	// Children retrieves the list of children nodes for a given node in the Zookeeper hierarchy.
	// It takes the path of the parent node and returns a list of child node names, the parent node's stat information,
	// and an error if the retrieval fails.
	Children(path string) ([]string, *zk.Stat, error)

	// ChildrenW retrieves the list of children nodes for a given node in the Zookeeper hierarchy
	// and sets up a watch on the parent node.
	// It takes the path of the parent node and returns a list of child node names,
	// a channel for receiving watch events, and an error if the retrieval or watch setup fails.
	ChildrenW(path string) ([]string, <-chan zk.Event, error)

	// AddAuth adds an authentication config to the connection.
	AddAuth(scheme string, auth []byte) error
}

// goZooKeeperConn is a wrapper of go-zookeeper
type goZooKeeperConn struct {
	conn *zk.Conn
}

// newGoZooKeeperConn create a goZooKeeperConn
func newGoZooKeeperConn() Connection {
	return new(goZooKeeperConn)
}

// Connect establishes a connection to the Zookeeper servers using go-zookeeper.
func (g *goZooKeeperConn) Connect(servers []string, sessionTimeout time.Duration, dialer zk.Dialer,
	opts ...ConnOption) (<-chan zk.Event, error) {
	c, ch, e := zk.Connect(
		servers,
		sessionTimeout,
		zk.WithLogger(&zkLogger{}),
		zk.WithLogInfo(true),
		zk.WithDialer(dialer),
		zk.WithMaxBufferSize(defaultZkBufferSize),
		zk.WithMaxConnBufferSize(defaultZkBufferSize),
	)
	if e != nil {
		log.Error().Msgf("failed to connect to zookeeper, err:%v", e)
		return nil, e
	}
	if c == nil {
		log.Error().Msgf("zk conn is nil")
		return nil, fmt.Errorf("zk conn is nil")
	}

	if g.conn != nil {
		log.Info().Msgf("closing old go-zookeeper conn")
		g.conn.Close()
	}
	g.conn = c
	return ch, e
}

// Close closes the Zookeeper connection.
func (g *goZooKeeperConn) Close() {
	if g.conn != nil {
		g.conn.Close()
		g.conn = nil
	}
}

// Create creates a new node in the Zookeeper hierarchy.
func (g *goZooKeeperConn) Create(path string, data []byte, flags int32, acl []zk.ACL) (string, error) {
	if g.conn == nil {
		return "", fmt.Errorf("invalid go-zookeeper conn")
	}
	return g.conn.Create(path, data, flags, acl)
}

// Delete deletes an existing node in the Zookeeper hierarchy.
func (g *goZooKeeperConn) Delete(path string, version int32) error {
	if g.conn == nil {
		return fmt.Errorf("invalid go-zookeeper conn")
	}
	return g.conn.Delete(path, version)
}

// Exists checks if a node exists in the Zookeeper hierarchy.
func (g *goZooKeeperConn) Exists(path string) (bool, *zk.Stat, error) {
	if g.conn == nil {
		return false, nil, fmt.Errorf("invalid go-zookeeper conn")
	}
	return g.conn.Exists(path)
}

// Get retrieves the data and stat information of a node in the Zookeeper hierarchy.
func (g *goZooKeeperConn) Get(path string) ([]byte, *zk.Stat, error) {
	if g.conn == nil {
		return []byte{}, nil, fmt.Errorf("invalid go-zookeeper conn")
	}
	return g.conn.Get(path)
}

// Children retrieves the list of children nodes for a given node in the Zookeeper hierarchy.
func (g *goZooKeeperConn) Children(path string) ([]string, *zk.Stat, error) {
	if g.conn == nil {
		return []string{}, nil, fmt.Errorf("invalid go-zookeeper conn")
	}
	return g.conn.Children(path)
}

// ChildrenW retrieves the list of children nodes for a given node in the Zookeeper hierarchy
func (g *goZooKeeperConn) ChildrenW(path string) ([]string, <-chan zk.Event, error) {
	if g.conn == nil {
		return []string{}, nil, fmt.Errorf("invalid go-zookeeper conn")
	}
	result, _, ch, err := g.conn.ChildrenW(path)
	return result, ch, err
}

// AddAuth adds an authentication config to the connection.
func (g *goZooKeeperConn) AddAuth(scheme string, auth []byte) error {
	if g.conn == nil {
		return fmt.Errorf("invalid go-zookeeper conn")
	}
	return g.conn.AddAuth(scheme, auth)
}
