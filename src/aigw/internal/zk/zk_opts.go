/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: zk opts implements options for zookeeper manager
 * Create: 2025-07-21
 */

// Package zk provides zookeeper management for AIGW.
package zk

import (
	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/pkg/crypto"
	"huawei.com/aigw/pkg/log"
)

// ZooKeeperOption is the option for ZooKeeper manager
type ZooKeeperOption func(mgr *ZooKeeperManager) error

// WithServiceAddress supplies service address
func WithServiceAddress(address string) ZooKeeperOption {
	return func(mgr *ZooKeeperManager) error {
		mgr.serviceAddress = address
		return nil
	}
}

// WithTlsAndDialer create tlsConfig and tlsDialer
func WithTlsAndDialer(config *base.ZookeeperConfig, keyDer []byte) ZooKeeperOption {
	if config.EnableTls {
		return func(mgr *ZooKeeperManager) error {
			var err error
			log.Debug().Msgf("[zk] init tlsCfg")
			mgr.tlsCfg, err = crypto.GenerateTlsCfgFromFile(config.CaFile, config.CrtFile,
				keyDer, config.ServerName)
			if err != nil {
				return err
			}
			log.Debug().Msgf("[zk] init tlsDialer")
			mgr.dialer = crypto.GenerateZKTlsDialer(mgr.tlsCfg)

			return nil
		}
	}
	return func(mgr *ZooKeeperManager) error {
		mgr.tlsCfg = nil
		return nil
	}
}

// WithUserPwd provides the user and password
func WithUserPwd(user string, pwd []byte) ZooKeeperOption {
	return func(mgr *ZooKeeperManager) error {
		mgr.password = make([]byte, len(pwd))
		copy(mgr.password, pwd)

		mgr.user = user
		return nil
	}
}
