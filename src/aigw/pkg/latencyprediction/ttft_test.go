/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: ttft prediction module
 * Create: 2025-12-18
 */
package latencyprediction

import (
	"math"
	"math/rand"
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test model initialization
func TestNewRLS(t *testing.T) {
	lambda := 1.0
	rls := NewRLS(lambda)

	if rls.n != 6 {
		t.Errorf("Expected 6 parameters, got %d\n", rls.n)
	}
	if len(rls.params) != 6 {
		t.Errorf("The length of the parameter slice should be 6, but got %d\n", len(rls.params))
	}
	if len(rls.p) != 6 || len(rls.p[0]) != 6 {
		t.Error("The covariance matrix should be 6x6")
	}
	if rls.lambda != lambda {
		t.Errorf("The forgetting factor does not match, expected %v, got %v\n", lambda, rls.lambda)
	}
	for i := 0; i < 6; i++ {
		if rls.p[i][i] != 1e6 {
			t.Errorf("Incorrect initial value for covariance matrix, position (%d,%d) should be 1e6, got %v", i, i, rls.p[i][i])
		}
	}
}

// Test feature vector construction
func TestConstructFeatures(t *testing.T) {
	rls := NewRLS(1.0)
	input, cached := 2, 3

	features := rls.constructFeatures(input, cached)

	if len(features) != 6 {
		t.Fatalf("The length of the feature vector should be 6, but got %d", len(features))
	}

	in, cac := float64(input), float64(cached)
	expected := []float64{
		in * in,
		cac * cac,
		in * cac,
		in,
		cac,
		1.0,
	}

	for i := range features {
		if features[i] != expected[i] {
			t.Errorf("Feature %d does not match, expected %v, got %v", i, expected[i], features[i])
		}
	}
}

// Test the prediction functionality
func TestPredict(t *testing.T) {
	rls := NewRLS(1.0)
	rls.params = []float64{1.0, 1.0, 1.0, 1.0, 1.0, 1.0}

	input, cached := 2, 3
	pred := rls.Predict(input, cached)

	expected := 25.0
	if pred != expected {
		t.Errorf("Prediction result is incorrect, expected %v, got %v", expected, pred)
	}
}

// Test the training functionality
func TestTrain(t *testing.T) {
	rls := NewRLS(1.0)

	sampleSize := 2000
	minVal, maxVal := 10, 1000
	for i := 0; i < sampleSize; i++ {
		input := minVal + rand.Intn(maxVal-minVal)
		cached := minVal + rand.Intn(maxVal-minVal)

		// Objective function: y = x1² + x2² + x1x2 + x1 + x2 + 1
		x1, x2 := float64(input), float64(cached)
		y := x1*x1 + x2*x2 + x1*x2 + x1 + x2 + 1.0

		rls.Train(input, cached, y)
	}

	expectedParams := []float64{1.0, 1.0, 1.0, 1.0, 1.0, 1.0}
	tolerance := 0.2
	for i := range rls.params {
		lower := expectedParams[i] * (1 - tolerance)
		upper := expectedParams[i] * (1 + tolerance)
		if rls.params[i] < lower || rls.params[i] > upper {
			t.Errorf("Parameter %d has insufficient convergence. Expected to be between [%v, %v], but got %v",
				i, lower, upper, rls.params[i])
		}
	}
}

// Test boundary cases
func TestEdgeCases(t *testing.T) {
	rls := NewRLS(1.0)

	// Zero-value input
	t.Run("zero inputs", func(t *testing.T) {
		rls.Train(0, 0, 1.0)
		pred := rls.Predict(0, 0)
		if pred < 0.5 || pred > 1.5 {
			t.Errorf("Abnormal prediction result for zero-value input, result: %v", pred)
		}
	})

	// Large-value input
	t.Run("large inputs", func(t *testing.T) {
		input, cached := 1000, 2000
		rls.Train(input, cached, 5000.0)
		pred := rls.Predict(input, cached)
		_ = pred
	})
}

// Test interface implementation
func TestTTFTPredictionImplementation(t *testing.T) {
	var predictor TTFTPrediction = NewRLS(1.0)

	input := 10
	cached := 20
	target := 30.0

	// Test interface method invocation
	predictor.Train(input, cached, target)
	pred := predictor.Predict(input, cached)

	if pred < target-1.0 || pred > target+1.0 {
		t.Errorf("The Predict result is outside the expected range: input(%d,%d), "+
			"target value %.2f, predicted value %.2f, allowed range [%.2f, %.2f]",
			input, cached, target, pred, target-1.0, target+1.0)
	}
}

// Test Clone functionality
func TestTTFTPrediction_Clone(t *testing.T) {
	rls := NewRLS(1.0)
	sampleSize := 2000
	minVal, maxVal := 10, 1000

	// Train the original predictor
	for i := 0; i < sampleSize; i++ {
		input := minVal + rand.Intn(maxVal-minVal)
		cached := minVal + rand.Intn(maxVal-minVal)

		// Objective function: y = x1² + x2² + x1x2 + x1 + x2 + 1
		x1, x2 := float64(input), float64(cached)
		y := x1*x1 + x2*x2 + x1*x2 + x1 + x2 + 1.0

		rls.Train(input, cached, y)
	}

	// Clone the predictor
	rls2 := rls.Clone()

	// Test that predictions are the same
	for i := 0; i < 100; i++ {
		input := minVal + rand.Intn(maxVal-minVal)
		cached := minVal + rand.Intn(maxVal-minVal)

		v1 := rls.Predict(input, cached)
		v2 := rls2.Predict(input, cached)

		assert.Equal(t, v1, v2)
	}

	// Test that modifying one doesn't affect the other
	rls.Train(500, 600, 1000.0)
	v1 := rls.Predict(500, 600)
	v2 := rls2.Predict(500, 600)
	assert.NotEqual(t, v1, v2)
}

// Test NewTTFTPredictor with different paths
func TestNewTTFTPredictor(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		predictor, err := NewTTFTPredictor("")
		assert.NoError(t, err)
		assert.NotNil(t, predictor)

		// Test that it can still predict
		pred := predictor.Predict(10, 20)
		assert.Equal(t, 0.0, pred) // Initially all params are zero
	})

	t.Run("non-existent path", func(t *testing.T) {
		predictor, err := NewTTFTPredictor("not_exist_path.txt")
		assert.Error(t, err)
		assert.Nil(t, predictor)
	})

	t.Run("valid path with data", func(t *testing.T) {
		// Create a temporary file with test data
		tmpFile, err := os.CreateTemp("", "ttft_test_*.txt")
		assert.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		content := "100, 50, 150.5\n200, 100, 300.2\n"
		_, err = tmpFile.WriteString(content)
		assert.NoError(t, err)
		tmpFile.Close()

		// Test NewTTFTPredictor
		predictor, err := NewTTFTPredictor(tmpFile.Name())
		assert.NoError(t, err)
		assert.NotNil(t, predictor)

		// Verify that training happened (params should not be all zeros)
		rls, ok := predictor.(*RLS)
		assert.True(t, ok)

		nonZero := false
		for _, p := range rls.params {
			if p != 0 {
				nonZero = true
				break
			}
		}
		assert.True(t, nonZero, "Parameters should be updated after pretraining")
	})
}

// Test multiple predictors independence
func TestMultiplePredictors(t *testing.T) {
	// Create two independent predictors
	predictor1 := NewRLS(1.0)
	predictor2 := NewRLS(1.0)

	// Train them differently
	for i := 0; i < 100; i++ {
		predictor1.Train(i, i+1, float64(i*2))
		predictor2.Train(i, i+1, float64(i*3))
	}

	// They should produce different predictions
	pred1 := predictor1.Predict(50, 51)
	pred2 := predictor2.Predict(50, 51)

	t.Logf("Predictor1 prediction: %v", pred1)
	t.Logf("Predictor2 prediction: %v", pred2)

	// 检查差异是否显著（大于1e-6）
	diff := math.Abs(pred1 - pred2)
	assert.Greater(t, diff, 1e-6,
		"Predictions from differently trained predictors should differ significantly")
}

// Test Predict with negative values (should return 0)
func TestPredictNegative(t *testing.T) {
	rls := NewRLS(1.0)
	// Set some parameters that could produce negative predictions
	rls.params = []float64{-10.0, 1.0, 1.0, 1.0, 1.0, 1.0}

	pred := rls.Predict(1, 1)
	assert.GreaterOrEqual(t, pred, 0.0, "Prediction should not be negative")
}

// Test ReadTtftData function
func TestReadTtftData(t *testing.T) {
	// Define test cases
	tests := []struct {
		name    string
		content string
		want    []*ttftTrainData
		wantErr bool
	}{
		{
			name:    "valid data",
			content: "12272, 11667, 1931.82\n23985, 14358, 5711.95",
			want: []*ttftTrainData{
				{input: 12272, cached: 11667, ttft: 1931.82},
				{input: 23985, cached: 14358, ttft: 5711.95},
			},
			wantErr: false,
		},
		{
			name:    "empty lines and spaces",
			content: "\n  1903, 1648, 466.77  \n\n",
			want: []*ttftTrainData{
				{input: 1903, cached: 1648, ttft: 466.77},
			},
			wantErr: false,
		},
		{
			name:    "invalid format (missing column)",
			content: "12272, 11667",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid data type (string instead of int)",
			content: "abc, 11667, 1931.82",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file for each test case
			tmpFile, err := os.CreateTemp("", "aigw_testdata_*.txt")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			// Write test content to the temp file
			if _, err := tmpFile.WriteString(tt.content); err != nil {
				t.Fatalf("failed to write to temp file: %v", err)
			}
			tmpFile.Close()

			// Execute the function
			got, err := readTtftData(tmpFile.Name())

			// Check for error expectations
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadTtftData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Compare results
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ReadTtftData() got = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test ReadTtftData with non-existent file
func TestReadTtftData_FileNotFound(t *testing.T) {
	_, err := readTtftData("non_existent_file.txt")
	assert.Error(t, err)
}
