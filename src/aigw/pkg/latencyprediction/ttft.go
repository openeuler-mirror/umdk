/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: ttft prediction module
 * Create: 2025-12-18
 */

package latencyprediction

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"huawei.com/aigw/pkg/log"
)

// TTFTPrediction define the interface for ttft predictor
type TTFTPrediction interface {
	// Predict ttft
	Predict(input, cached int) float64
	// Train with ground-truth ttft
	Train(input, cached int, y float64)
	// Clone a new predictor
	Clone() TTFTPrediction
}

type ttftTrainData struct {
	input  int
	cached int
	ttft   float64
}

const expectPretrainTTFTParamsNum int = 3
const ttftModelCoeffNum int = 6

// RLS (Recursive Least Squares) algorithm support train and predict ttft for online prediction,
// which updates model parameters recursively using new ttft data
type RLS struct {
	params []float64   // Polynomial coefficients: [a, b, c, d, e, f]
	p      [][]float64 // Covariance matrix
	lambda float64     // Forgetting factor: Setting to 1 means no forgetting mechanism, and all data contribute equally
	n      int         // Number of parameters: Set to 6
}

// NewTTFTPredictor creates and initializes a new TTFT predictor
func NewTTFTPredictor(path string) (TTFTPrediction, error) {
	if path == "" {
		log.Info().Msg("empty ttft data path, create ttft predictor without pretrain data!")
		return NewRLS(1.0), nil
	}

	data, err := readTtftData(path)
	if err != nil {
		log.Error().Msgf("read ttft data failed with path %s!", path)
		return nil, err
	}

	rlsPredictor := NewRLS(1.0)
	if rlsPredictor == nil {
		return nil, fmt.Errorf("failed to create RLS predictor")
	}

	for _, d := range data {
		rlsPredictor.Train(d.input, d.cached, d.ttft)
	}

	if rlsPredictor == nil {
		return nil, fmt.Errorf("predictor became nil after training")
	}

	log.Info().Msgf("init ttft predictor successfully and pretrained with %s, model params %v",
		path, rlsPredictor.params)

	return rlsPredictor, nil
}

// readTtftData opens a txt file and parses its content into a slice of ttftTrainData pointers
func readTtftData(filePath string) ([]*ttftTrainData, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var result []*ttftTrainData
	scanner := bufio.NewScanner(file)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// parse the pretrain data
		parts := strings.Split(line, ",")
		if len(parts) != expectPretrainTTFTParamsNum {
			return nil, fmt.Errorf("invalid format at line %d: expected 3 fields, got %d", lineNum, len(parts))
		}

		input, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, fmt.Errorf("error parsing 'input' at line %d: %v", lineNum, err)
		}

		cached, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("error parsing 'cached' at line %d: %v", lineNum, err)
		}

		ttft, err := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
		if err != nil {
			return nil, fmt.Errorf("error parsing 'ttft' at line %d: %v", lineNum, err)
		}

		result = append(result, &ttftTrainData{
			input:  input,
			cached: cached,
			ttft:   ttft,
		})
	}

	// check for errors during scanning (e.g., file system issues)
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %v", err)
	}

	return result, nil
}

// NewRLS creates a new RLS instance
// It initializes the necessary parameters for the RLS algorithm.
func NewRLS(lambda float64) *RLS {
	// y = a*input² + b*cached² + c*input*cached + d*input + e*cached + f
	n := ttftModelCoeffNum
	params := make([]float64, n)
	p := make([][]float64, n)
	for i := range p {
		p[i] = make([]float64, n)
		p[i][i] = 1e6
	}

	return &RLS{
		params: params,
		p:      p,
		lambda: lambda,
		n:      n,
	}
}

// Predict calculates the predicted value using the current model parameters
// and the input feature vector.
func (rls *RLS) Predict(input, cached int) float64 {
	x1 := float64(input)
	x2 := float64(cached)

	result := rls.params[0]*x1*x1 +
		rls.params[1]*x2*x2 +
		rls.params[2]*x1*x2 +
		rls.params[3]*x1 +
		rls.params[4]*x2 +
		rls.params[5]*1.0
	if result < 0 {
		result = 0
	}
	return result
}

// Train updates the RLS model using the input data and target value.
func (rls *RLS) Train(input, cached int, y float64) {
	features := rls.constructFeatures(input, cached)
	rls.update(features, y)
}

// Construct the feature vector
func (rls *RLS) constructFeatures(input, cached int) []float64 {
	in := float64(input)
	cac := float64(cached)
	return []float64{
		in * in,
		cac * cac,
		in * cac,
		in,
		cac,
		1.0,
	}
}

// update RLS parameters
func (rls *RLS) update(features []float64, y float64) {
	// Calculate the gain vector k
	k := make([]float64, rls.n)
	phiTP := make([]float64, rls.n)
	for i := 0; i < rls.n; i++ {
		sum := 0.0
		sum += features[0]*rls.p[0][i] +
			features[1]*rls.p[1][i] +
			features[2]*rls.p[2][i] +
			features[3]*rls.p[3][i] +
			features[4]*rls.p[4][i] +
			features[5]*rls.p[5][i]
		phiTP[i] = sum
	}

	phiTPPhi := phiTP[0]*features[0] +
		phiTP[1]*features[1] +
		phiTP[2]*features[2] +
		phiTP[3]*features[3] +
		phiTP[4]*features[4] +
		phiTP[5]*features[5]

	denominator := rls.lambda + phiTPPhi
	for i := 0; i < rls.n; i++ {
		sum := 0.0
		sum += rls.p[i][0]*features[0] +
			rls.p[i][1]*features[1] +
			rls.p[i][2]*features[2] +
			rls.p[i][3]*features[3] +
			rls.p[i][4]*features[4] +
			rls.p[i][5]*features[5]
		k[i] = sum / denominator
	}

	// Calculate the error and update the parameters
	errVal := y - features[0]*rls.params[0] -
		features[1]*rls.params[1] -
		features[2]*rls.params[2] -
		features[3]*rls.params[3] -
		features[4]*rls.params[4] -
		features[5]*rls.params[5]

	rls.params[0] += k[0] * errVal
	rls.params[1] += k[1] * errVal
	rls.params[2] += k[2] * errVal
	rls.params[3] += k[3] * errVal
	rls.params[4] += k[4] * errVal
	rls.params[5] += k[5] * errVal

	// Update the covariance matrix P
	for i := 0; i < rls.n; i++ {
		rls.p[i][0] = (rls.p[i][0] - k[i]*phiTP[0]) / rls.lambda
		rls.p[i][1] = (rls.p[i][1] - k[i]*phiTP[1]) / rls.lambda
		rls.p[i][2] = (rls.p[i][2] - k[i]*phiTP[2]) / rls.lambda
		rls.p[i][3] = (rls.p[i][3] - k[i]*phiTP[3]) / rls.lambda
		rls.p[i][4] = (rls.p[i][4] - k[i]*phiTP[4]) / rls.lambda
		rls.p[i][5] = (rls.p[i][5] - k[i]*phiTP[5]) / rls.lambda
	}
}

// Clone a new predictor
func (rls *RLS) Clone() TTFTPrediction {
	newRLS := &RLS{
		params: make([]float64, rls.n),
		p:      make([][]float64, rls.n),
		lambda: rls.lambda,
		n:      rls.n,
	}
	copy(newRLS.params, rls.params)
	for i := range rls.p {
		newRLS.p[i] = make([]float64, rls.n)
		copy(newRLS.p[i], rls.p[i])
	}
	return newRLS
}
