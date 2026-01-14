/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: define the interfaces of vectorizer
 * Create: 2025-06-30
 */

// Package vectorizer provides functions of vectorization for AIGW.
package vectorizer

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"sync"
	"unicode"

	"huawei.com/aigw/pkg/log"
)

const filePermissions = 0640

// SplitToCharsWithFilter split the input string and filter out spaces
func SplitToCharsWithFilter(text string) []string {
	if text == "" {
		return nil
	}

	var result []string
	for _, char := range text {
		charStr := string(char)
		// filter out spaces
		if !unicode.IsSpace(char) {
			result = append(result, charStr)
		}
	}

	return result
}

type tfidfParameters struct {
	GVocab []string
	GIdf   map[string]float64
}

// Save the vocabulary and idf matrix of training stage
var (
	gParams   tfidfParameters
	vocabLock sync.RWMutex
	isTrained bool
)

func countTermFreqAndDocFreq(docs [][]string) ([]map[string]int, map[string]int) {
	termFreqs := make([]map[string]int, len(docs))
	docFreq := make(map[string]int)
	for i, doc := range docs {
		termFreqs[i] = make(map[string]int)
		uniqueWords := make(map[string]bool)

		for _, word := range doc {
			if word == "" {
				continue
			}
			termFreqs[i][word]++
			if uniqueWords[word] != true {
				uniqueWords[word] = true
				docFreq[word]++
			}
		}
	}
	return termFreqs, docFreq
}

// TrainTfidf pretrain the tf-idf model to extract topK keywords
func TrainTfidf(docs [][]string, topK int) ([]string, [][]float64) {
	if len(docs) == 0 || topK <= 0 {
		log.Error().Msg("invalid input parameters")
		return nil, nil
	}

	// count the term frequency and doc frequency
	termFreqs, docFreq := countTermFreqAndDocFreq(docs)

	tfidfScores := make(map[string]float64)
	for i := range docs {
		totalWords := 0
		for _, count := range termFreqs[i] {
			totalWords += count
		}

		if totalWords == 0 {
			log.Warn().Msgf("training tf-idf, skip empty input doc %d", i)
			continue
		}

		for word, count := range termFreqs[i] {
			// tf-idf
			tf := float64(count) / float64(totalWords)
			// use smooth_idf
			idf := math.Log(float64(len(docs)+1)/float64(docFreq[word]+1)) + 1
			score := tf * idf

			if current, exists := tfidfScores[word]; !exists || score > current {
				tfidfScores[word] = score
			}
		}
	}

	// select topK words
	selectedWords := selectTopKWords(tfidfScores, topK)

	// create the vocabulary
	vocabMap := make(map[string]int)
	for i, word := range selectedWords {
		vocabMap[word] = i
	}

	// calculate and save idf for selected keywords
	idfValues := make(map[string]float64)
	for word := range vocabMap {
		idfValues[word] = math.Log(float64(len(docs)+1)/float64(docFreq[word]+1)) + 1
	}

	vocabLock.Lock()
	gParams.GVocab = selectedWords
	gParams.GIdf = idfValues
	isTrained = true
	vocabLock.Unlock()

	// calculate the tf-idf of input docs
	finalMatrix := make([][]float64, len(docs))
	for i := range docs {
		finalMatrix[i] = make([]float64, len(selectedWords))
		for j := range finalMatrix[i] {
			finalMatrix[i][j] = 0
		}

		totalWords := 0
		for _, count := range termFreqs[i] {
			totalWords += count
		}
		if totalWords == 0 {
			log.Warn().Msgf("calculate weight matrix failed, input string array %d is empty", i)
			continue
		}

		for word, count := range termFreqs[i] {
			if idx, exists := vocabMap[word]; exists {
				tf := float64(count) / float64(totalWords)
				finalMatrix[i][idx] = tf * idfValues[word]
			}
		}

		// L2 normalize
		finalMatrix[i] = normalizeL2(finalMatrix[i])
	}

	return selectedWords, finalMatrix
}

func normalizeL2(vector []float64) []float64 {
	sumSquares := 0.0
	for _, val := range vector {
		sumSquares += val * val
	}

	if sumSquares == 0 {
		return vector
	}

	norm := math.Sqrt(sumSquares)
	normalized := make([]float64, len(vector))
	for i, val := range vector {
		normalized[i] = val / norm
	}

	return normalized
}

func selectTopKWords(scores map[string]float64, k int) []string {
	type wordScore struct {
		word  string
		score float64
	}

	var ws []wordScore
	for word, score := range scores {
		ws = append(ws, wordScore{word: word, score: score})
	}

	sort.Slice(ws, func(i, j int) bool {
		return ws[i].score > ws[j].score
	})

	if k > len(ws) {
		k = len(ws)
	}

	result := make([]string, k)
	for i := 0; i < k; i++ {
		result[i] = ws[i].word
	}

	return result
}

// PredictTfidf predict the tf-idf weight of the input string array
func PredictTfidf(doc []string) ([]float64, error) {
	vocabLock.RLock()
	defer vocabLock.RUnlock()

	if !isTrained {
		return nil, fmt.Errorf("tf-idf model has not been trained yet")
	}

	termFreq := make(map[string]int)
	totalWords := 0
	for _, word := range doc {
		if word == "" {
			continue
		}
		termFreq[word]++
		totalWords++
	}

	if totalWords == 0 {
		return nil, fmt.Errorf("input doc len is zero")
	}

	result := make([]float64, len(gParams.GVocab))
	for i, word := range gParams.GVocab {
		count := termFreq[word]
		if count == 0 {
			result[i] = 0
			continue
		}

		tf := float64(count) / float64(totalWords)
		idf, exist := gParams.GIdf[word]
		if exist {
			result[i] = tf * idf
		} else {
			result[i] = 0
		}
	}

	return normalizeL2(result), nil
}

// LoadVectorizer load the parameters of vectorizer from input file
func LoadVectorizer(filename string) error {
	if filename == "" {
		return fmt.Errorf("input vectorizer file path is null")
	}

	bytes, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	err = json.Unmarshal(bytes, &gParams)
	if err != nil {
		return err
	}
	isTrained = true
	log.Info().Msgf("load pretrained vectorizer from %s successfully", filename)
	return nil
}

// ClearVectorizer clear the parameters of vectorizer
func ClearVectorizer() error {
	isTrained = false
	gParams.GVocab = nil
	gParams.GIdf = nil
	return nil
}
