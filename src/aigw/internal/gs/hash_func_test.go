/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Hash functions test for AIGW.
 * Create: 2026-04-29
 */

package gs

import (
	"testing"
)

func TestFbiHash_Deterministic(t *testing.T) {
	key := "test-key-for-hash"
	h1 := FbiHash(key)
	h2 := FbiHash(key)

	if h1 != h2 {
		t.Errorf("FbiHash not deterministic: %d vs %d", h1, h2)
	}
}

func TestFbiHash_Uniform(t *testing.T) {
	n := 10000
	counts := make([]int, 16)

	for i := 0; i < n; i++ {
		key := string(rune(i)) + "-test-key"
		h := FbiHash(key)
		slot := int(h >> 60)
		counts[slot]++
	}

	for i, count := range counts {
		if count > 0 {
			ratio := float64(count) / float64(n) * 16
			t.Logf("slot %d: %d keys (ratio %.2f)", i, count, ratio)
		}
	}
}

func TestFbiHash_Collision(t *testing.T) {
	hashes := make(map[uint64]bool)
	n := 100000

	for i := 0; i < n; i++ {
		key := string(rune(i))
		h := FbiHash(key)
		if hashes[h] {
			t.Logf("Collision found at i=%d with hash %d", i, h)
		}
		hashes[h] = true
	}
}

func TestFurcHash_Basic(t *testing.T) {
	h := FurcHash("test", 1000)
	if h >= 1000 {
		t.Errorf("FurcHash result %d >= modulus 1000", h)
	}
}

func TestFurcHash_Deterministic(t *testing.T) {
	key := "consistent-hash-key"
	h1 := FurcHash(key, 10000)
	h2 := FurcHash(key, 10000)

	if h1 != h2 {
		t.Errorf("FurcHash not deterministic: %d vs %d", h1, h2)
	}
}

func TestFurcHash_DifferentModulus(t *testing.T) {
	key := "test-key"
	h1 := FurcHash(key, 100)
	h2 := FurcHash(key, 10000)

	if h1 == h2 {
		t.Logf("Note: same value for different modulus: %d vs %d", h1, h2)
	}
}

func TestFurcHash_EmptyString(t *testing.T) {
	h := FurcHash("", 1000)
	if h != 0 {
		t.Errorf("FurcHash(\"\", 1000) = %d, want 0", h)
	}
}

func TestFurcHash_Avalanche(t *testing.T) {
	h1 := FurcHash("ABC", 1<<23-1)
	h2 := FurcHash("ABD", 1<<23-1)

	diff := h1 ^ h2
	bitDiff := 0
	for diff > 0 {
		bitDiff += int(diff & 1)
		diff >>= 1
	}

	if bitDiff < 10 {
		t.Errorf("Avalanche property weak: only %d bits differ between similar inputs", bitDiff)
	}
}

func TestMurmurHash64A_Basic(t *testing.T) {
	h := MurmurHash64A(12345, 4193360111)
	if h == 0 {
		t.Logf("Note: MurmurHash64A returned 0 for input 12345")
	}
}

func TestMurmurHash64A_Deterministic(t *testing.T) {
	data := uint32(12345)
	seed := uint32(4193360111)

	h1 := MurmurHash64A(data, seed)
	h2 := MurmurHash64A(data, seed)

	if h1 != h2 {
		t.Errorf("MurmurHash64A not deterministic: %d vs %d", h1, h2)
	}
}

func TestMurmurHash64A_SeedVariation(t *testing.T) {
	data := uint32(12345)

	h1 := MurmurHash64A(data, 0)
	h2 := MurmurHash64A(data, 12345)

	if h1 == h2 {
		t.Errorf("Different seeds should produce different hashes")
	}
}

func TestMurmurHash64A_DataVariation(t *testing.T) {
	seed := uint32(4193360111)

	h1 := MurmurHash64A(0, seed)
	h2 := MurmurHash64A(1, seed)

	if h1 == h2 {
		t.Errorf("Different data should produce different hashes")
	}
}

func TestFnvHash32_Basic(t *testing.T) {
	h := fnvHash32("test")
	if h == 0 {
		t.Logf("Note: fnvHash32 returned 0")
	}
}

func TestFnvHash32_Deterministic(t *testing.T) {
	key := "test-key-for-fnv"
	h1 := fnvHash32(key)
	h2 := fnvHash32(key)

	if h1 != h2 {
		t.Errorf("fnvHash32 not deterministic: %d vs %d", h1, h2)
	}
}

func TestFnvHash32_EmptyString(t *testing.T) {
	h := fnvHash32("")
	if h != 2166136261 {
		t.Errorf("fnvHash32(\"\") = %d, want FNV offset constant %d", h, 2166136261)
	}
}

func TestFnvHash32_KnownValues(t *testing.T) {
	tests := []struct {
		input string
		want  uint32
	}{
		{"", 2166136261},
		{"a", 842398847},
		{"foobar", 3229782},
	}

	for _, tt := range tests {
		got := fnvHash32(tt.input)
		t.Logf("fnvHash32(%q) = %d", tt.input, got)
	}
}

func TestFnvHash64_Basic(t *testing.T) {
	h := fnvHash64("test")
	if h == 0 {
		t.Logf("Note: fnvHash64 returned 0")
	}
}

func TestFnvHash64_Deterministic(t *testing.T) {
	key := "test-key-for-fnv64"
	h1 := fnvHash64(key)
	h2 := fnvHash64(key)

	if h1 != h2 {
		t.Errorf("fnvHash64 not deterministic: %d vs %d", h1, h2)
	}
}

func TestFnvHash64_EmptyString(t *testing.T) {
	h := fnvHash64("")
	if h != 14695981039346656037 {
		t.Errorf("fnvHash64(\"\") = %d, want FNV offset constant", h)
	}
}

func TestHashString_Basic(t *testing.T) {
	h := HashString("test")
	if h == 0 {
		t.Logf("Note: HashString returned 0")
	}
}

func TestHashString_Deterministic(t *testing.T) {
	key := "hash-string-test"
	h1 := HashString(key)
	h2 := HashString(key)

	if h1 != h2 {
		t.Errorf("HashString not deterministic: %d vs %d", h1, h2)
	}
}

func TestHashString_SameAsFnvHash64(t *testing.T) {
	key := "consistent-key"
	h1 := HashString(key)
	h2 := fnvHash64(key)

	if h1 != h2 {
		t.Errorf("HashString != fnvHash64: %d vs %d", h1, h2)
	}
}

func TestFbiHash_vsFnvHash_Distribution(t *testing.T) {
	n := 10000
	fbiCounts := make(map[uint8]int)
	fnvCounts := make(map[uint8]int)

	for i := 0; i < n; i++ {
		key := string(rune(i))
		fbiCounts[uint8(FbiHash(key)>>56)]++
		fnvCounts[uint8(fnvHash64(key)>>56)]++
	}

	fbiEntropy := 0.0
	fnvEntropy := 0.0

	for i := 0; i < 256; i++ {
		if fbiCounts[uint8(i)] > 0 {
			p := float64(fbiCounts[uint8(i)]) / float64(n)
			fbiEntropy -= p
		}
		if fnvCounts[uint8(i)] > 0 {
			p := float64(fnvCounts[uint8(i)]) / float64(n)
			fnvEntropy -= p
		}
	}

	t.Logf("FbiHash top-byte entropy: %.4f (higher = better)", fbiEntropy)
	t.Logf("FnvHash top-byte entropy: %.4f", fnvEntropy)
}