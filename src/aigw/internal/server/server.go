/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Server provides north interfaces for AIGW.
 * Create: 2025-06-05
 */

// Package server provides north interfaces for AIGW.
package server

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"huawei.com/aigw/internal/alarmmonitor"
	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/core"
	"huawei.com/aigw/internal/modelmonitor"
	"huawei.com/aigw/internal/zk"
	"huawei.com/aigw/pkg/crypto"
	"huawei.com/aigw/pkg/log"
	"huawei.com/aigw/pkg/sock"
	"huawei.com/aigw/pkg/utils"
)

const (
	numberOfSplit   = 2
	splitKeyIndex   = 0
	splitValueIndex = 1
	argsStartIndex  = 1
	hmacKeyLen      = 32
	aesKeyLen       = 16

	commonStringLen = 256

	defaultCfgPath = "/etc/aigw/conf/aigw.json"
)

// keyData records key and password temporarily, clear it to zero after use
type keyData struct {
	apiHmacKey []byte
	apiAesKey  []byte

	insHmacKey []byte
	insAesKey  []byte

	monitorHmacKey  []byte
	dataSyncHmacKey []byte

	zookeeperUser     string
	zookeeperPassword []byte
	zookeeperTlsKey   []byte
}

type serverTask func(*base.AigwConfig) error

// settings contains the launch settings
var settings = struct {
	cfgPath string
}{
	cfgPath: defaultCfgPath,
}

type aigwServerHandler struct {
	cfgMgr     *core.AigwConfigManager
	aigwMgr    *core.AigwManager
	zkMgr      *zk.ZooKeeperManager
	monitorMgr *alarmmonitor.MonitorManager
	modelMgr   *modelmonitor.ModelManager

	httpServer *HttpServer
	crypto     keyData
}

var serverHandler = aigwServerHandler{}

var (
	sigCh chan os.Signal = make(chan os.Signal, 1)
)

// PrintUsage Print Usage
func PrintUsage() {
	fmt.Printf("Usage: %v [OPTION]...\n", os.Args[0])
	fmt.Println("Options:")
	fmt.Printf("   --config    config file path, just like --config=path, default: %v\n", defaultCfgPath)
	fmt.Printf("   -h/--help   diplay this usage of aigw \n")
	fmt.Println("")
}

var optionHandlers = map[string]func(string) error{
	"--config": handleConfig,
}

func handleConfig(value string) error {
	absPath, err := utils.ValidateFilePath(value)
	if err != nil {
		return err
	}
	settings.cfgPath = absPath
	return nil
}

func handleHMACKey(value string) error {
	if len([]byte(value)) != hmacKeyLen {
		return fmt.Errorf("the length of hmac key is invalid")
	}

	return nil
}

func handleAESKey(value string) error {
	if len([]byte(value)) != aesKeyLen {
		return fmt.Errorf("the length of aes key is invalid")
	}

	return nil
}

func parseLaunchSettings() error {
	args := os.Args[argsStartIndex:] // skip the command name

	for _, arg := range args {
		parts := strings.SplitN(arg, "=", numberOfSplit)
		if len(parts) != numberOfSplit {
			return fmt.Errorf("invalid format of argument, should be key=value style," +
				" value should not contains '='")
		}

		key, value := parts[splitKeyIndex], parts[splitValueIndex]
		handler, ok := optionHandlers[key]
		if !ok {
			return fmt.Errorf("unknown option %v for %v", key, os.Args[0])
		}

		if err := handler(value); err != nil {
			return err
		}
	}

	return nil
}

func initLog(cfg *base.GlobalConfig) error {
	var options []log.AigwLogOption

	if cfg.LogPath != "" {
		options = append(options, log.Path(cfg.LogPath))
	}
	if cfg.LogLevel != "" {
		options = append(options, log.Level(cfg.LogLevel))
	}

	return log.InitLogger(options...)
}

func validateCryptoData(data *base.CryptoData) error {
	logErrAndReturnErr := func(ctx string, err error) error {
		log.Error().Msgf("%v, err: %v", ctx, err)
		return fmt.Errorf("%v, err: %v", ctx, err)
	}

	// hmac can't be empty
	hmacList := []struct {
		name  string
		value string
	}{
		{name: "ApiHmacKey", value: data.ApiHmacKey},
		{name: "InsHmacKey", value: data.InsHmacKey},
	}

	if len(data.MonitorHmacKey) > 0 {
		hmacList = append(hmacList, struct {
			name  string
			value string
		}{name: "MonitorHmacKey", value: data.MonitorHmacKey})
	}

	if len(data.DataSyncHmacKey) > 0 {
		hmacList = append(hmacList, struct {
			name  string
			value string
		}{name: "DataSyncHmacKey", value: data.DataSyncHmacKey})
	}

	for _, hmac := range hmacList {
		if err := handleHMACKey(hmac.value); err != nil {
			return logErrAndReturnErr(fmt.Sprintf("%v is invalid", hmac.name), err)
		}
	}

	// aes is optional
	if len(data.ApiAesKey) > 0 {
		if err := handleAESKey(data.ApiAesKey); err != nil {
			return logErrAndReturnErr("api aes key is invalid", err)
		}
	}
	if len(data.InsAesKey) > 0 {
		if err := handleAESKey(data.InsAesKey); err != nil {
			return logErrAndReturnErr("ins aes key is invalid", err)
		}
	}

	// zk user and password are optional
	userLen, pwdLen := len([]byte(data.ZookeeperUser)), len([]byte(data.ZookeeperPassword))
	if userLen > commonStringLen {
		return logErrAndReturnErr("invalid zk user len",
			fmt.Errorf("len exceeds the max %v", commonStringLen))
	}
	if pwdLen > commonStringLen {
		return logErrAndReturnErr("invalid zk password len", fmt.Errorf("len exceeds the max"))
	}

	return nil
}

func constructKeyData(tempData *base.CryptoData) {
	c := &serverHandler.crypto

	c.apiHmacKey = []byte(tempData.ApiHmacKey)
	c.apiAesKey = []byte(tempData.ApiAesKey)
	c.insHmacKey = []byte(tempData.InsHmacKey)
	c.insAesKey = []byte(tempData.InsAesKey)
	c.monitorHmacKey = []byte(tempData.MonitorHmacKey)
	c.dataSyncHmacKey = []byte(tempData.DataSyncHmacKey)
	c.zookeeperPassword = []byte(tempData.ZookeeperPassword)
	c.zookeeperTlsKey = []byte(tempData.ZookeeperTlsKey)

	// create a new string to avoid using tempData
	c.zookeeperUser = fmt.Sprintf("%v", tempData.ZookeeperUser)
}

func loadCryptoData(aigwConfig *base.AigwConfig) error {
	cfg := &aigwConfig.GlobalConfig
	if strings.TrimSpace(cfg.CryptoSock) == "" {
		// crypto sock is empty, disable loading crypto data
		log.Info().Msgf("cryptoSock is empty, skip loading crypto data")
		return nil
	}

	uds, err := sock.NewUnixSock(cfg.CryptoSock)
	if err != nil {
		log.Error().Msgf("failed to NewUnixSock: %v, err: %v", cfg.CryptoSock, err)
		return err
	}
	defer uds.Close()

	data, err := uds.ReadData()
	if err != nil {
		log.Error().Msgf("failed to read from unix sock: %v, err: %v", cfg.CryptoSock, err)
		return err
	}

	// Parse the JSON
	var tempData base.CryptoData
	if err := json.Unmarshal(data, &tempData); err != nil {
		log.Error().Msgf("failed to unmarshal crypto data, err: %v", err)
		return err
	}

	// validate
	if err := validateCryptoData(&tempData); err != nil {
		log.Error().Msgf("failed to validate crypto data, err: %v", err)
		return err
	}

	constructKeyData(&tempData)
	return nil
}

func initZooKeeperManager(globalCfg *base.GlobalConfig, cfg *base.ZookeeperConfig) (*zk.ZooKeeperManager, error) {
	cbs := zk.EventCallback{
		RegInferInsCb:   serverHandler.aigwMgr.RegisterInstance,
		UnRegInferInsCb: serverHandler.aigwMgr.UnregisterInstance,
	}

	serviceAddress := net.JoinHostPort(globalCfg.Host, globalCfg.Port)

	log.Info().Msgf("start to create zookeeper manager, server: %v, serviceAddress %v",
		cfg.Address, serviceAddress)
	zkMgr, err := zk.NewZookeeperManager(cfg, cbs,
		zk.WithServiceAddress(serviceAddress),
		zk.WithTlsAndDialer(cfg, serverHandler.crypto.zookeeperTlsKey),
		zk.WithUserPwd(serverHandler.crypto.zookeeperUser, serverHandler.crypto.zookeeperPassword),
	)
	utils.ZeroBytes(serverHandler.crypto.zookeeperTlsKey)
	if err != nil {
		return nil, err
	}
	if zkMgr == nil {
		return nil, fmt.Errorf("failed to new ZookeeperManager")
	}

	if err := zkMgr.Start(); err != nil {
		return nil, err
	}

	// clear key to zero after use
	utils.ZeroBytes(serverHandler.crypto.zookeeperPassword)

	log.Info().Msgf("create zookeeper manager successfully, server: %v, serviceAddress %v",
		cfg.Address, serviceAddress)
	return zkMgr, nil
}

func initMonitorManager(globalCfg *base.GlobalConfig, monitorCfg *base.MonitorConfig,
	mgr *crypto.HmacManager) (*alarmmonitor.MonitorManager, error) {
	hostIP := globalCfg.Host
	monitorMgr, err := alarmmonitor.NewMonitorManger(monitorCfg,
		alarmmonitor.WithServiceAddress(hostIP),
		alarmmonitor.WithHmac(mgr))
	if err != nil {
		return nil, err
	}

	if err := monitorMgr.Start(); err != nil {
		return nil, err
	}
	log.Info().Msgf("create monitor manager successfully, address: %v, alarmPath:%v",
		monitorCfg.Address, monitorCfg.AlarmPath)
	return monitorMgr, nil
}

func initModelManager(dsCfg *base.DataSyncConfig, hmacMgr *crypto.HmacManager) (*modelmonitor.ModelManager, error) {
	url := "http://" + dsCfg.Address + dsCfg.Path
	log.Info().Msgf("init modelManager, target Url is: %v", url)
	cbs := modelmonitor.EventCallback{
		RegisterModelCb:   serverHandler.aigwMgr.RegisterModel,
		UnregisterModelCb: serverHandler.aigwMgr.UnregisterModel,
	}
	modelMgr := modelmonitor.NewModelManager(url, cbs, hmacMgr, dsCfg.Interval)
	err := modelMgr.Start()
	return modelMgr, err
}

func startManagers(aigwConfig *base.AigwConfig) error {
	log.Info().Msgf("starting managers for AIGW")

	key := serverHandler.crypto

	// start monitor
	monitorCfg := serverHandler.cfgMgr.GetMonitorConfig()
	monitorAddress := strings.TrimSpace(monitorCfg.Address)
	if monitorAddress != "" {
		hmacMgr := crypto.NewHmacManager(key.monitorHmacKey,
			crypto.WithHmacSchema(aigwConfig.GlobalConfig.SecuritySchema))
		if !hmacMgr.EnableHmac() {
			log.Warn().Msgf("alarm monitor do not use hmac")
		}
		// clear key to zero after use
		utils.ZeroBytes(key.monitorHmacKey)
		monitorManger, err := initMonitorManager(&aigwConfig.GlobalConfig, monitorCfg, hmacMgr)
		if err != nil {
			log.Error().Msgf("failed to init monitor manager, err: %v", err)
			return err
		}
		serverHandler.monitorMgr = monitorManger
		// if monitor is set up, register report alarm func to alarm logger manger.
		log.SetAlarmLogCb(serverHandler.monitorMgr.PutAlarmMessage)
		log.Info().Msgf("alarm log callback registered")
	}

	aigwMgr, err := core.NewAigwManager(aigwConfig,
		core.WithHmac(crypto.NewHmacManager(key.insHmacKey,
			crypto.WithHmacSchema(aigwConfig.GlobalConfig.SecuritySchema))),
		core.WithAes(crypto.NewAesManager(key.insAesKey,
			crypto.WithAesSchema(aigwConfig.GlobalConfig.SecuritySchema))))
	if err != nil {
		log.Error().Msgf("failed to create aigw manager, err: %v", err)
		return err
	}
	if !aigwMgr.HmacMgr.EnableHmac() {
		log.Warn().Msgf("the connect with instance in aigwManager do not use hmac")
	}
	if !aigwMgr.AesMgr.EnableAes() {
		log.Warn().Msgf("the connect with instance in aigwManager do not use aes-gcm")
	}
	// clear key to zero after use
	utils.ZeroBytes(key.insHmacKey)
	utils.ZeroBytes(key.insAesKey)
	serverHandler.aigwMgr = aigwMgr

	if err := aigwMgr.Init(); err != nil {
		log.Error().Msgf("failed to init aigw manager, err: %v", err)
		return err
	}

	dsCfg := serverHandler.cfgMgr.GetDataSyncConfig()
	dsAddress := strings.TrimSpace(dsCfg.Address)
	if dsAddress != "" {
		hmacMgr := crypto.NewHmacManager(key.dataSyncHmacKey,
			crypto.WithHmacSchema(aigwConfig.GlobalConfig.SecuritySchema))
		if !hmacMgr.EnableHmac() {
			log.Warn().Msgf("dataSync do not use hmac")
		}
		// clear key to zero after use
		utils.ZeroBytes(key.dataSyncHmacKey)
		modelMgr, err := initModelManager(dsCfg, hmacMgr)
		if err != nil {
			log.Error().Msgf("failed to init model manager, err: %v", err)
			return err
		}
		serverHandler.modelMgr = modelMgr
	}

	zkCfg := serverHandler.cfgMgr.GetZkConfig()
	zkAddress := strings.TrimSpace(zkCfg.Address)
	if zkAddress != "" {
		zkMgr, err := initZooKeeperManager(&aigwConfig.GlobalConfig, zkCfg)
		if err != nil {
			log.Error().Msgf("failed to init zk manager, err: %v", err)
			return err
		}
		if !zkCfg.EnableTls {
			log.Warn().Msgf("zookeeper do not use tls")
		}
		serverHandler.zkMgr = zkMgr
	}

	return nil
}

func stopManagers() {
	if serverHandler.zkMgr != nil {
		serverHandler.zkMgr.Stop()
	}
	if serverHandler.modelMgr != nil {
		serverHandler.modelMgr.Stop()
	}
	if serverHandler.aigwMgr != nil {
		serverHandler.aigwMgr.Uninit()
	}
	if serverHandler.monitorMgr != nil {
		serverHandler.monitorMgr.Stop()
	}
}

func startHttpServer(aigwConfig *base.AigwConfig) error {
	maxConcurrency = aigwConfig.Limits.Concurrency

	hmacMgr := crypto.NewHmacManager(serverHandler.crypto.apiHmacKey,
		crypto.WithHmacSchema(aigwConfig.GlobalConfig.SecuritySchema))
	aesMgr := crypto.NewAesManager(serverHandler.crypto.apiAesKey,
		crypto.WithAesSchema(aigwConfig.GlobalConfig.SecuritySchema))
	httpServer := NewHttpServer(serverHandler.aigwMgr, aigwConfig.GlobalConfig.Host, aigwConfig.GlobalConfig.Port)
	httpServer.serHmacMgr = hmacMgr
	httpServer.serAesMgr = aesMgr
	if !hmacMgr.EnableHmac() {
		log.Warn().Msgf("aigw api do not use hmac")
	}
	if !aesMgr.EnableAes() {
		log.Warn().Msgf("aigw api do not use aes-gcm")
	}
	if err := httpServer.Start(); err != nil {
		log.Error().Msgf("failed to start httpServer, err: %v", err)
		httpServer.Stop()
		return err
	}
	serverHandler.httpServer = httpServer

	// clear key to zero after use
	utils.ZeroBytes(serverHandler.crypto.apiHmacKey)
	utils.ZeroBytes(serverHandler.crypto.apiAesKey)
	return nil
}

func startLogger(aigwConfig *base.AigwConfig) error {
	// log config will be checked in log.InitLogger
	return initLog(&aigwConfig.GlobalConfig)
}

func validateConfig(aigwConfig *base.AigwConfig) error {
	m := serverHandler.cfgMgr

	// validate the config
	if err := m.ValidateConfig(aigwConfig); err != nil {
		log.Error().Msgf("server start error: %v", err)
		return err
	}

	m.PrintConfig()
	return nil
}

func launchTasks(aigwConfig *base.AigwConfig, errCh chan<- error, tasks ...serverTask) {
	for _, task := range tasks {
		err := task(aigwConfig)
		if err != nil {
			errCh <- err
			return
		}
	}
	errCh <- nil
	log.Info().Msgf("server tasks have been started")
}

func stopTasks() {
	if serverHandler.httpServer != nil {
		serverHandler.httpServer.Stop()
	}

	stopManagers()
	log.Info().Msgf("server tasks have been stopped")
}

// Execute is the entry point to run AIGW.
func Execute() error {
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	args := os.Args[argsStartIndex:]
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			PrintUsage()
			return nil
		}
	}
	if err := parseLaunchSettings(); err != nil {
		return err
	}

	configMgr := core.NewAigwConfigManager()
	if err := configMgr.LoadConfig(settings.cfgPath); err != nil {
		fmt.Printf("load config failed, err: %v\n", err)
		return err
	}
	serverHandler.cfgMgr = configMgr

	errChan := make(chan error, 1)
	go launchTasks(configMgr.GetAigwConfig(), errChan,
		startLogger,
		validateConfig,
		loadCryptoData,
		startManagers,
		// httpServer should be the last one
		startHttpServer,
	)

	for {
		select {
		case sig := <-sigCh:
			log.Info().Msgf("exit for received signal %v", sig)
			stopTasks()
			return nil
		case err := <-errChan:
			if err == nil {
				continue
			}
			stopTasks()
			return err
		}
	}
}
