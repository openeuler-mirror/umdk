/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: vectorizer test
 * Create: 2025-06-30
 */

// Package vectorizer provides functions of vectorization for AIGW.
package vectorizer

import (
	"reflect"
	"testing"
)

const (
	globalTopK          = 2
	validVectorizerPath = "../../test/vectorizer/pretrained_vector.json"
)

func TestSplitToCharsWithFilter(t *testing.T) {
	emptyTestStr := ""
	ret := SplitToCharsWithFilter(emptyTestStr)
	if ret != nil {
		t.Errorf("Split empty string error")
	}

	normalTestStr := "Hello world!"
	equal := reflect.DeepEqual(
		SplitToCharsWithFilter(normalTestStr), []string{"H", "e", "l", "l", "o", "w", "o", "r", "l", "d", "!"})
	if equal != true {
		t.Errorf("Split empty string error")
	}
}

func TestCountTermFreqAndDocFreq(t *testing.T) {
	docs := [][]string{{"apple", "is", "good"}, {"appletree", "is", "good"}}
	termFreqs, docFreq := countTermFreqAndDocFreq(docs)
	if termFreqs[0]["apple"] != 1 || termFreqs[0]["is"] != 1 || termFreqs[0]["good"] != 1 ||
		termFreqs[1]["appletree"] != 1 || termFreqs[1]["is"] != 1 || termFreqs[1]["good"] != 1 {
		t.Errorf("termFreqs is not correct")
	}

	if docFreq["apple"] != 1 || docFreq["is"] != 2 || docFreq["good"] != 2 || docFreq["appletree"] != 1 {
		t.Errorf("docFreq is not correct")
	}
}

func TestTrainTfidf(t *testing.T) {
	selectedWords, finalMatrix := TrainTfidf([][]string{}, 0)
	if selectedWords != nil || finalMatrix != nil {
		t.Errorf("TrainTfidf check input params failed")
	}

	selectedWords, finalMatrix = TrainTfidf([][]string{}, globalTopK)
	if selectedWords != nil || finalMatrix != nil {
		t.Errorf("TrainTfidf check input params failed")
	}

	selectedWords, finalMatrix = TrainTfidf([][]string{{"a", "b"}, {"c", "d"}}, 0)
	if selectedWords != nil || finalMatrix != nil {
		t.Errorf("TrainTfidf check input params failed")
	}

	selectedWords, finalMatrix =
		TrainTfidf([][]string{{"apple", "is", "good"}, {"appletree", "is", "good"}}, globalTopK)
	if selectedWords == nil || finalMatrix == nil || len(selectedWords) != globalTopK {
		t.Errorf("TrainTfidf gen selectedWords & finalMatrix failed")
	}
}

func TestPredictTfidf(t *testing.T) {
	feature, err := PredictTfidf([]string{})
	if feature != nil || err == nil {
		t.Errorf("PredictTfidf convert empty input string to feature failed")
	}

	feature, err = PredictTfidf([]string{"apple", "is", "good"})
	if len(feature) != globalTopK || err != nil {
		t.Errorf("PredictTfidf convert input string to feature failed")
	}

	// test unpretrained
	ClearVectorizer()
	feature, err = PredictTfidf([]string{"apple", "is", "good"})
	if feature != nil || err == nil {
		t.Errorf("PredictTfidf convert empty input string to feature failed")
	}
}

func TestLoadVectorizer(t *testing.T) {
	if LoadVectorizer("") == nil {
		t.Errorf("LoadVectorizer check params failed")
	}

	if LoadVectorizer("InvalidPath") == nil {
		t.Errorf("LoadVectorizer check params failed")
	}

	if LoadVectorizer(validVectorizerPath) != nil {
		t.Errorf("LoadVectorizer failed")
	}

	ClearVectorizer()
}
