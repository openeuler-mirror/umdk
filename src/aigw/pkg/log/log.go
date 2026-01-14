/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: log main file
 * Create: 2025-05-30
 */

// Package log use for init logger format
package log

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"

	"huawei.com/aigw/pkg/utils"
)

const logFileMode = 0640

var loggerM *logManager

// Config for logger
type Config struct {
	// Enable console logger
	ConsoleloggerEnabled bool

	// Directory to log to to when filelogger is enabled
	Directory string

	// Filename is the name of the logfile which will be placed inside the directory
	Filename string

	// MaxSize the max size in MB of the logfile before it's rolled
	MaxSize int

	// MaxBackups the max number of rolled files to keep
	MaxBackups int

	// DefaultLevel the default log level
	DefaultLevel logrus.Level
}

const (
	defaultBackUps = 200
)

var config = Config{
	ConsoleloggerEnabled: false,
	MaxSize:              defaultMaxSize,
	MaxBackups:           defaultBackUps,
	Directory:            "/var/log/aigw",
	DefaultLevel:         InfoLevel,
}

// SetLogLevel set log level
func SetLogLevel(level string) error {
	l, err := logrus.ParseLevel(level)
	if err != nil {
		return err
	}
	logger.Level = l
	return nil
}

// InitLogger init logger
func InitLogger(options ...AigwLogOption) error {
	for _, opt := range options {
		if e := opt(); e != nil {
			return e
		}
	}
	return initLogger()
}

func initLogger() error {
	var err error
	var ws []io.Writer
	if config.Directory == "" {
		config.Directory, err = filepath.Abs("./log")
		if err != nil {
			return fmt.Errorf("failed to get default directory, err: %v", err)
		}
	}

	config.Filename = filepath.Base(os.Args[0]) + ".log"
	logFileName := path.Join(config.Directory, config.Filename)
	if err = initLogFile(logFileName); err != nil {
		return fmt.Errorf("failed to init log file %s, err: %v", logFileName, err)
	}
	if err = initLogFile(path.Join(config.Directory, alarmFile)); err != nil {
		return fmt.Errorf("failed to init alarm file %s, err: %v", alarmFile, err)
	}
	output := newRollingWriter(config)
	ws = append(ws, output)

	if config.ConsoleloggerEnabled {
		ws = append(ws, os.Stderr)
	}

	mw := io.MultiWriter(ws...)
	var formatter = &Formatter{TimestampFormat: time.RFC3339Nano}
	formatter.FormatTimestamp = func(i interface{}) string {
		return fmt.Sprintf("[%s]", i)
	}
	formatter.FormatLevel = func(i interface{}) string {
		return fmt.Sprintf("[%s]", i)
	}
	formatter.FormatField = func(k string, i interface{}) string {
		return fmt.Sprintf("%v:%v", k, i)
	}
	formatter.FormatCaller = func(file, function, line string) string {
		return fmt.Sprintf("[%s:%s] [%s]", filepath.Base(file), line, filepath.Base(function))
	}
	loggerM.setFormatter(formatter)
	logger = &logrus.Logger{
		Formatter: formatter,
		Out:       mw,
		Level:     config.DefaultLevel,
	}
	logger.SetNoLock()
	newAlarmLogger(formatter)
	Info().
		Bool("consoleLogger", config.ConsoleloggerEnabled).Str("logDirectory", config.Directory).
		Str("logFilename", config.Filename).Str("logLevel", config.DefaultLevel.String()).
		Int("logMaxSize", config.MaxSize).Int("logMaxBackups", config.MaxBackups).
		Msg("init logger success.")
	return nil
}

func initLogFile(filePath string) error {
	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			f, e := os.Create(filePath)
			if e != nil {
				return e
			}
			err = f.Chmod(logFileMode)
			if err != nil {
				return err
			}
			if e = f.Close(); e != nil {
				return e
			}
		} else {
			return err
		}
	}
	return os.Chmod(filePath, logFileMode)
}

func newRollingWriter(config Config) io.Writer {
	return &RotateWriter{
		Filename:   path.Join(config.Directory, config.Filename),
		MaxSize:    int64(config.MaxSize),
		MaxBackups: config.MaxBackups,
	}
}

func init() {
	utils.SetOpenFilesLimit()

	loggerM = newLogManager(context.Background())
	loggerM.start()
}