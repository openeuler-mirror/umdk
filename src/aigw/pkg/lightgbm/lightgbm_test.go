/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: lightgbm interface test
 * Create: 2025-5-30
 */

package lightgbm

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	modelPath = "../../test/lightgbm/lgbm_text_classifier.txt"
	input     = "../../test/lightgbm/input.txt"
	output    = "../../test/lightgbm/output.txt"
)

func TestNewBooster(t *testing.T) {
	_, err := NewBooster(BoosterParams{ModelFile: ""})
	require.NotNil(t, err)
	booster, err := NewBooster(BoosterParams{ModelFile: "123.txt"})
	require.NotNil(t, err)
	booster, err = NewBooster(BoosterParams{ModelFile: modelPath})
	require.Nil(t, err)
	require.NotNil(t, booster)
	BoosterDestroy(booster)
}

func ReadDataFromFile(filePath string, fieldLength int) ([][]float64, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var data [][]float64
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) != fieldLength {
			return nil, &LineFormatError{Line: lineNum, Expected: fieldLength, Actual: len(fields)}
		}

		row := make([]float64, fieldLength)
		for i, field := range fields {
			val, err := strconv.ParseFloat(field, 64)
			if err != nil {
				return nil, &ValueParseError{Line: lineNum, Column: i + 1, Value: field}
			}
			row[i] = val
		}
		data = append(data, row)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return data, nil
}

// 自定义错误类型
type LineFormatError struct {
	Line     int
	Expected int
	Actual   int
}

func (e *LineFormatError) Error() string {
	return strconv.Itoa(e.Line) + "行数据格式错误: 需要" +
		strconv.Itoa(e.Expected) + "个数值，实际" + strconv.Itoa(e.Actual) + "个"
}

type ValueParseError struct {
	Line   int
	Column int
	Value  string
}

func (e *ValueParseError) Error() string {
	return strconv.Itoa(e.Line) + "行" + strconv.Itoa(e.Column) +
		"列数值转换错误: '" + e.Value + "'"
}

func indexOfMaxFloat(data []float64) int {
	if len(data) == 0 {
		return -1
	}

	maxIndex := 0
	maxValue := data[0]

	for i := 1; i < len(data); i++ {
		if data[i] > maxValue {
			maxValue = data[i]
			maxIndex = i
		}
	}

	return maxIndex
}

func TestPredict(t *testing.T) {
	booster, err := NewBooster(BoosterParams{ModelFile: modelPath})
	require.Nil(t, err)
	defer BoosterDestroy(booster)

	// invalid features
	_, err = booster.Predict([]float64{})
	assert.Error(t, err)

	// 读取文件
	inputs, err := ReadDataFromFile(input, 300)
	require.Nil(t, err)
	wants, err := ReadDataFromFile(output, 7)
	require.Nil(t, err)

	for i, input := range inputs {
		t.Run(fmt.Sprintf("predict%v", i), func(t *testing.T) {
			preds, err := booster.Predict(input)
			require.Nil(t, err)
			for j, v := range wants[i] {
				if math.Abs(v-preds[j]) > 0.01 {
					t.Errorf("excepted:%v, got:%v", v, preds[j])
				}
			}
		})
	}
}

func TestBoosterDestroy(t *testing.T) {
	// Test destroy nil booster
	BoosterDestroy(nil)

	// Test destroy booster with nil handler
	booster := &Booster{handler: nil}
	BoosterDestroy(booster)
	// Should not panic
}

func TestIndexOfMaxFloat(t *testing.T) {
	tests := []struct {
		name     string
		input    []float64
		expected int
	}{
		{"empty", []float64{}, -1},
		{"single", []float64{1.0}, 0},
		{"first_max", []float64{5.0, 3.0, 2.0}, 0},
		{"middle_max", []float64{1.0, 9.0, 3.0}, 1},
		{"last_max", []float64{1.0, 2.0, 10.0}, 2},
		{"all_same", []float64{5.0, 5.0, 5.0}, 0},
		{"negative", []float64{-5.0, -3.0, -1.0}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := indexOfMaxFloat(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestReadDataFromFile(t *testing.T) {
	// Test with non-existent file
	_, err := ReadDataFromFile("/non/existent/file.txt", 10)
	assert.Error(t, err)

	// Test with valid file but wrong field length
	tmpFile, err := os.CreateTemp("", "test_*.txt")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString("1 2 3\n4 5 6\n")
	assert.NoError(t, err)
	tmpFile.Close()

	_, err = ReadDataFromFile(tmpFile.Name(), 10)
	assert.Error(t, err)
	assert.IsType(t, &LineFormatError{}, err)

	// Test with invalid number
	tmpFile2, err := os.CreateTemp("", "test_*.txt")
	assert.NoError(t, err)
	defer os.Remove(tmpFile2.Name())

	_, err = tmpFile2.WriteString("1 2 abc\n")
	assert.NoError(t, err)
	tmpFile2.Close()

	_, err = ReadDataFromFile(tmpFile2.Name(), 3)
	assert.Error(t, err)
	assert.IsType(t, &ValueParseError{}, err)
}
