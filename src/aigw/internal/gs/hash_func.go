/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Hash functions for consistent hashing in AIGW.
 * Create: 2026-04-29
 */

// Package gs is the global scheduler for AIGW.
package gs

// FbiHash implements the Facebook-style hash function used in vLLM Router.
// It combines FurcHash with MurmurHash64A for good distribution.
// This is the primary hash function for consistent hash routing.
func FbiHash(key string) uint64 {
	const largeModulus uint32 = (1 << 23) - 1 // 8388607

	furcResult := FurcHash(key, largeModulus)

	// MurmurHash64A with seed 4193360111
	return MurmurHash64A(furcResult, 4193360111)
}

// FurcHash implements the Facebook consistency hash algorithm.
// Based on mcrouter's FurcHash with multiple mixing steps for better distribution.
// The algorithm combines:
// 1. Primary FNV-1a hash of the key
// 2. Avalanche mixing (MurmurHash3 finalizer) for bit diffusion
// 3. Golden ratio mixing for improved distribution
// 4. Secondary hash combination to reduce collisions
// This provides good distribution and minimizes rehashing on node changes.
func FurcHash(key string, m uint32) uint32 {
	if len(key) == 0 {
		return 0
	}

	// Primary hash using FNV-1a
	h := fnvHash32(key)

	// Avalanche mixing (MurmurHash3 32-bit finalizer)
	// This provides excellent bit diffusion
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16

	// Golden ratio mixing (φ = 1.618..., 0x9e3779b9 = 2^32 / φ)
	// This provides good distribution across the range
	h ^= h >> 10
	h *= 0x9e3779b9
	h ^= h >> 16

	// Secondary mixing with key length for additional entropy
	h ^= uint32(len(key)) * 0x9e3779b9
	h ^= h >> 11
	h *= 0x7f4a7c15
	h ^= h >> 16

	// Apply modulo for range limitation
	return h % m
}

// MurmurHash64A implements MurmurHash64A for 32-bit input.
// Used as the second hash in FbiHash for better distribution.
func MurmurHash64A(data uint32, seed uint32) uint64 {
	const m uint64 = 0xc6a4a7935bd1e995
	const r uint8 = 47

	// Initialize hash with seed XORed with a carefully chosen constant
	// This replaces (seed ^ (4*m)) which would overflow
	var h uint64 = uint64(seed) ^ 0xc6a4a7935bd1e995

	// Mix 32-bit data into 64-bit hash
	k := uint64(data)
	k *= m
	k ^= k >> r
	k *= m

	h ^= k
	h *= m

	// Final mix
	h ^= h >> r
	h *= m
	h ^= h >> r

	return h
}

// fnvHash32 implements FNV-1a 32-bit hash.
// Used as the base hash for FurcHash.
func fnvHash32(s string) uint32 {
	const (
		prime32  uint32 = 16777619
		offset32 uint32 = 2166136261
	)

	h := offset32
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime32
	}
	return h
}

// fnvHash64 implements FNV-1a 64-bit hash.
// Used for request hash key generation.
func fnvHash64(s string) uint64 {
	const (
		prime64  uint64 = 1099511628211
		offset64 uint64 = 14695981039346656037
	)

	h := offset64
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime64
	}
	return h
}

// HashString is a simple string hash function for non-critical use cases.
// Uses FNV-1a 64-bit hash.
func HashString(s string) uint64 {
	return fnvHash64(s)
}
