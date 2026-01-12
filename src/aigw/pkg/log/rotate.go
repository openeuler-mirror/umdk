/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: chown implementation in non linux platform
 * Create: 2025-6-4
 */

package log

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// RotateWriter rotate writer
type RotateWriter struct {
	Filename   string
	MaxSize    int64
	MaxBackups int // 为0表示不限制备份文件数目
	size       int64
	file       *os.File
	sync.Mutex
}

const (
	defaultMaxSize      = 10
	defaultPem          = 0640
	compressPem         = 0440
	defaultDirPem       = 0750
	backUpTimeFormat    = "2006-01-02T15-04-05.000"
	compressSuffix      = ".gz"
	defaultAlarmSize    = 10  // default alarm log size is 10 MB
	defaultAlarmBackUps = 100 // default alarm back ups is 100
	alarmFile           = "alarm.log"
)

var (
	megaByte int64 = 1024 * 1024 // 1024*1024 bytes
)

func (w *RotateWriter) maxSize() int64 {
	if w.MaxSize == 0 {
		return defaultMaxSize * megaByte
	}
	return megaByte * w.MaxSize
}

func (w *RotateWriter) prefixAndExt() (string, string) {
	filename := filepath.Base(w.Filename)
	ext := filepath.Ext(filename)
	prefix := filename[:len(filename)-len(ext)] + "-"
	return prefix, ext
}

func (w *RotateWriter) backupName() string {
	dir := filepath.Dir(w.Filename)
	prefix, ext := w.prefixAndExt()
	return filepath.Join(dir, fmt.Sprintf("%s%s%s", prefix,
		time.Now().Format(backUpTimeFormat), ext))
}

func (w *RotateWriter) createNewFile(name string, info os.FileInfo, useDefaultPem bool) error {
	pem := info.Mode()
	if useDefaultPem {
		pem = defaultPem
	}
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, pem)
	if err != nil {
		return err
	}
	err = f.Close()
	if err != nil {
		return err
	}
	if err = os.Chmod(name, pem); err != nil {
		return err
	}
	return chown(name, info)
}

func (w *RotateWriter) isBackupLog(name, prefix, ext string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	if !strings.HasSuffix(name, ext) {
		return false
	}
	return true
}

func (w *RotateWriter) getOldLogFiles() ([]string, error) {
	files, err := os.ReadDir(filepath.Dir(w.Filename))
	if err != nil {
		return nil, err
	}
	var logFiles []string
	prefix, ext := w.prefixAndExt()
	for _, f := range files {
		if f.IsDir() {
			continue
		}

		if w.isBackupLog(f.Name(), prefix, ext) {
			logFiles = append(logFiles, f.Name())
			continue
		}

		if w.isBackupLog(f.Name(), prefix, ext+compressSuffix) {
			logFiles = append(logFiles, f.Name())
		}
	}
	sort.Strings(logFiles)
	return logFiles, nil
}

func (w *RotateWriter) checkBackUpCnt() error {
	files, err := w.getOldLogFiles()
	if err != nil {
		return err
	}

	if w.MaxBackups >= len(files) {
		return nil
	}

	// delete old backups
	remove := files[:len(files)-w.MaxBackups] // delete old logs
	dir := filepath.Dir(w.Filename)
	for _, fName := range remove {
		removeErr := os.Remove(filepath.Join(dir, fName))
		if err == nil && removeErr != nil {
			err = removeErr
		}
	}
	return err
}

func (w *RotateWriter) changeCompressPerm(file string) error {
	_, e := os.Stat(file)
	if e == nil {
		e = os.Chmod(file, defaultPem)
		if e != nil {
			return os.Remove(file)
		}
	}
	return nil
}

func (w *RotateWriter) checkAndCompress() error {
	if w.MaxBackups == 0 { // 为0时不限制转储个数
		return nil
	}

	// directory may do not exist, so we should check once
	err := w.checkDict()
	if err != nil {
		return err
	}

	files, err := w.getOldLogFiles()
	if err != nil {
		return err
	}

	// compress logs having not been compressed
	dir := filepath.Dir(w.Filename)
	for _, f := range files {
		if strings.HasSuffix(f, compressSuffix) {
			continue
		}

		fn := filepath.Join(dir, f)

		// if compressed file already exist, add write permit to it
		if e := w.changeCompressPerm(fn + compressSuffix); e != nil {
			if err != nil {
				err = e
			}
			continue
		}

		e := w.compress(fn, fn+compressSuffix)
		if e == nil {
			// remove original backup log file
			if e = os.Remove(fn); e != nil && err == nil {
				err = e
			}
		}
		if err == nil && e != nil {
			err = e
		}
	}

	return w.checkBackUpCnt()
}

func (w *RotateWriter) compress(src, dst string) (err error) {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}
	defer func() {
		if e := f.Close(); e != nil {
			err = fmt.Errorf("%v, close error %v", err, e)
		}
	}()

	fi, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("failed to stat log file: %v", err)
	}

	if err := w.createNewFile(dst, fi, true); err != nil {
		return fmt.Errorf("failed to create compressed log file: %v", err)
	}

	// if compress failed, remove compressed log file
	defer func() {
		if err != nil {
			err = fmt.Errorf("failed to compress log file: %v", err)
			if e := os.Remove(dst); e != nil { // 转储失败，删除新建的文件
				err = fmt.Errorf("%v, remove error %v", err, e)
			}
		}
	}()

	gzInfo, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, defaultPem)
	if err != nil {
		return fmt.Errorf("failed to open compressed log file: %v", err)
	}
	defer func() {
		if e := gzInfo.Close(); e != nil {
			err = fmt.Errorf("%v, close error %v", err, e)
		}
	}()

	gz := gzip.NewWriter(gzInfo)
	defer func() {
		if e := gz.Close(); e != nil {
			err = fmt.Errorf("%v, close error %v", err, e)
		}
	}()

	if _, e := io.Copy(gz, f); e != nil {
		return e
	}
	if e := os.Chmod(dst, compressPem); e != nil {
		return e
	}
	return
}

// checkDict try to create a directory if dict doest not exist
func (w *RotateWriter) checkDict() error {
	err := os.MkdirAll(filepath.Dir(w.Filename), defaultDirPem)
	if err != nil {
		return fmt.Errorf("create log directory error %v", err)
	}
	err = os.Chmod(filepath.Dir(w.Filename), defaultDirPem)
	if err != nil {
		return err
	}
	return nil
}

func (w *RotateWriter) openNewAndBackup() error {
	err := w.checkDict()
	if err != nil {
		return err
	}
	mode := os.FileMode(defaultPem)
	info, err := os.Stat(w.Filename)
	if err == nil {
		mode = info.Mode()
		backUpName := w.backupName()
		if err = os.Rename(w.Filename, backUpName); err != nil {
			return fmt.Errorf("rename log file error %v", err)
		}
		// 创建新的文件并继承之前的用户组、文件权限
		err = w.createNewFile(w.Filename, info, false)
		if err != nil {
			return err
		}

		// change permit of backupFile to 0440
		err = os.Chmod(backUpName, compressPem)
		if err != nil {
			return err
		}
	}
	f, err := os.OpenFile(w.Filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("open new log file error %v", err)
	}
	if err = os.Chmod(w.Filename, mode); err != nil {
		return err
	}
	w.file = f
	w.size = 0
	return nil
}

func (w *RotateWriter) openExistOrNewFile(wLen int64) error {
	if e := w.checkAndCompress(); e != nil { // check and rotate
		return e
	}

	if w.Filename == "" {
		return fmt.Errorf("log file name is empty")
	}
	info, err := os.Stat(w.Filename)
	if os.IsNotExist(err) {
		return w.openNewAndBackup()
	}

	if err != nil {
		return fmt.Errorf("get log file info error %v", err)
	}
	if info.Size()+wLen >= w.maxSize() {
		return w.rotate()
	}
	file, err := os.OpenFile(w.Filename, os.O_APPEND|os.O_WRONLY, defaultPem)
	if err != nil {
		return w.openNewAndBackup() // open fail, just ignore it and open a new one
	}
	w.file = file
	w.size = info.Size()
	return nil
}

func (w *RotateWriter) close() error {
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

func (w *RotateWriter) rotate() error {
	if err := w.close(); err != nil {
		return err
	}
	if err := w.openNewAndBackup(); err != nil {
		return err
	}
	return w.checkAndCompress() // 转储完之后，检查一次转储文件个数
}

// Write write bytes to file
func (w *RotateWriter) Write(content []byte) (int, error) {
	w.Lock()
	defer w.Unlock()

	writeLength := int64(len(content))
	if writeLength > w.maxSize() {
		return 0, fmt.Errorf("write length %d exceeds max size %d", writeLength, w.maxSize())
	}

	if w.file == nil {
		if err := w.openExistOrNewFile(writeLength); err != nil {
			return 0, err
		}
	}

	// rotate log
	if w.size+writeLength > w.maxSize() {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}

	n, err := w.file.Write(content)
	w.size += int64(n)
	return n, err
}

// Close close
func (w *RotateWriter) Close() error {
	w.Lock()
	defer w.Unlock()
	return w.close()
}
