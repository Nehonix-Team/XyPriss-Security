/***************************************************************************
 * XyPriss Security Core - High Performance Security Library
 *
 * @author NEHONIX (https://github.com/Nehonix-Team)
 * @license Nehonix Open Source License (NOSL)
 *
 * Copyright (c) 2025 NEHONIX. All rights reserved.
 *
 * This License governs the use, modification, and distribution of software
 * provided by NEHONIX under its open source projects.
 * NEHONIX is committed to fostering collaborative innovation while strictly
 * protecting its intellectual property rights.
 ****************************************************************************/

// Package lwe implements Learning With Errors (LWE) key generation and sampling
// primitives suitable for production use in post-quantum cryptographic protocols.
//
// Security properties:
//   - Error sampling uses a proper Centered Binomial Distribution (CBD) with η=2,
//     matching the CRYSTALS-Kyber / ML-KEM specification (FIPS 203).
//   - Uniform sampling uses rejection sampling to eliminate modular bias entirely.
//   - All randomness is sourced from crypto/rand (CSPRNG).
//   - Secret vectors are zeroized on release via Zeroize().
//   - No use of math/big in hot paths — pure integer arithmetic.
//
// Parameters:
//   - DefaultParams uses N=512, Q=12289 (standard LWE, NIST PQ candidate dimensions).
//   - For ML-KEM compatibility, use N=256, Q=3329.
//
// Reference: NIST FIPS 203 (ML-KEM), Section 4.2 (CBD sampling), Section 4.3 (uniform).
package lwe

import (
	"crypto/rand"
	"errors"
	"io"
)

// Params defines the LWE instance parameters.
type Params struct {
	N uint32 // Lattice dimension (e.g. 512, 768, 1024)
	Q uint32 // Prime modulus (e.g. 12289, 3329)
	// Eta controls the CBD error distribution: coefficients are in [-η, η].
	// η=2 is the ML-KEM standard. Higher η = more noise = higher security, lower correctness.
	Eta uint32
}

// DefaultParams are conservative production LWE parameters.
// N=512, Q=12289, η=2 — matching NewHope/NIST Round 1 dimensions.
var DefaultParams = Params{N: 512, Q: 12289, Eta: 2}

// KyberParams matches the ML-KEM (FIPS 203) inner parameters exactly.
var KyberParams = Params{N: 256, Q: 3329, Eta: 2}

// SecretVector holds a secret LWE vector with zeroization support.
// Always call Zeroize() when done to clear secret material from memory.
type SecretVector struct {
	Coeffs []int32
	params Params
}

// Zeroize overwrites the secret vector with zeros.
// Must be called when the secret is no longer needed.
func (s *SecretVector) Zeroize() {
	for i := range s.Coeffs {
		s.Coeffs[i] = 0
	}
}

// PublicVector holds a public (uniform) vector modulo Q.
type PublicVector struct {
	Coeffs []uint32
	params Params
}

// GenerateSecret generates a random secret vector s of dimension p.N,
// with coefficients sampled from the CBD(η) distribution.
// Returns an error if the system CSPRNG fails.
func GenerateSecret(p Params) (*SecretVector, error) {
	coeffs, err := sampleCBDVector(p.N, p.Eta)
	if err != nil {
		return nil, err
	}
	return &SecretVector{Coeffs: coeffs, params: p}, nil
}

// SampleErrorVector samples an error vector of length n from CBD(η).
// Suitable for use as the LWE error term e in (A·s + e).
func SampleErrorVector(p Params) ([]int32, error) {
	return sampleCBDVector(p.N, p.Eta)
}

// SampleUniform generates a uniformly random vector of length n modulo q
// using rejection sampling. This is strictly unbiased — no modular reduction
// artifacts.
//
// Rejection sampling loop: sample random bytes, accept if < floor(2^k / q) * q
// to ensure uniform distribution over [0, q).
func SampleUniform(p Params) (*PublicVector, error) {
	if p.Q == 0 {
		return nil, errors.New("lwe: modulus Q must be non-zero")
	}
	v := make([]uint32, p.N)
	for i := range v {
		val, err := sampleUniformUint32(p.Q)
		if err != nil {
			return nil, err
		}
		v[i] = val
	}
	return &PublicVector{Coeffs: v, params: p}, nil
}

// SampleCBD samples a single value from the Centered Binomial Distribution
// with parameter η (eta). Result is in [-η, η].
//
// Algorithm (per FIPS 203, Algorithm 7):
//   Read 2η bits. Let a = popcount(lower η bits), b = popcount(upper η bits).
//   Output a - b.
//
// This is indistinguishable from a discrete Gaussian for small η,
// and is the standard in CRYSTALS-Kyber / ML-KEM.
func SampleCBD(eta uint32) (int32, error) {
	if eta == 0 || eta > 8 {
		return 0, errors.New("lwe: eta must be in [1, 8]")
	}
	// We need 2*eta bits. Read ceil(2*eta / 8) bytes.
	byteCount := (2*eta + 7) / 8
	buf := make([]byte, byteCount)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return 0, errors.New("lwe: failed to read random bytes: " + err.Error())
	}

	// Pack bytes into a uint64 for bit manipulation
	var bits uint64
	for i, b := range buf {
		bits |= uint64(b) << (uint(i) * 8)
	}

	// Mask to exactly 2*eta bits
	mask := (uint64(1) << (2 * eta)) - 1
	bits &= mask

	// a = popcount of lower eta bits, b = popcount of upper eta bits
	lowerMask := (uint64(1) << eta) - 1
	a := popcount64(bits & lowerMask)
	b := popcount64((bits >> eta) & lowerMask)

	return int32(a) - int32(b), nil
}

// --- LWE operations ---

// InnerProduct computes the inner product <a, s> mod q,
// where a is a public vector and s is a secret vector.
// Both must have the same dimension and use the same params.
func InnerProduct(a *PublicVector, s *SecretVector) (uint32, error) {
	if a.params.N != s.params.N {
		return 0, errors.New("lwe: dimension mismatch")
	}
	q := uint64(a.params.Q)
	var acc uint64
	for i := range a.Coeffs {
		// s.Coeffs[i] can be negative: add Q to normalize to [0, Q)
		sv := uint64((int64(s.Coeffs[i])%int64(q) + int64(q))) % q
		acc = (acc + uint64(a.Coeffs[i])*sv) % q
	}
	return uint32(acc), nil
}

// --- Internal helpers ---

// sampleCBDVector samples n values from CBD(eta).
func sampleCBDVector(n, eta uint32) ([]int32, error) {
	out := make([]int32, n)
	// For efficiency, read all randomness in one call.
	// Each sample needs 2*eta bits = eta/4 bytes (rounded up).
	// For eta=2: 4 bits per sample, 2 samples per byte.
	// We use the batch-optimized path for eta=2 (most common case).
	if eta == 2 {
		return sampleCBDEta2Batch(n)
	}
	// Generic path for other eta values
	for i := range out {
		v, err := SampleCBD(eta)
		if err != nil {
			// Zeroize what we've produced so far before returning
			for j := range out {
				out[j] = 0
			}
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}

// sampleCBDEta2Batch samples n values from CBD(2) using a batched approach.
// Each byte encodes 2 samples: 4 bits each (bits 0-3 for sample i, bits 4-7 for i+1).
// This avoids syscall overhead per coefficient.
func sampleCBDEta2Batch(n uint32) ([]int32, error) {
	// Each sample uses 4 bits (2*eta=4). Two samples per byte.
	byteCount := (n + 1) / 2
	buf := make([]byte, byteCount)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, errors.New("lwe: CSPRNG failure in CBD sampling: " + err.Error())
	}
	defer func() {
		// Zeroize the random buffer immediately after use
		for i := range buf {
			buf[i] = 0
		}
	}()

	out := make([]int32, n)
	for i := uint32(0); i < n; i++ {
		var nibble byte
		if i%2 == 0 {
			nibble = buf[i/2] & 0x0F
		} else {
			nibble = (buf[i/2] >> 4) & 0x0F
		}
		// CBD(2): a = popcount(bits[0:2]), b = popcount(bits[2:4])
		a := popcount8(nibble & 0x03)      // bits 0-1
		b := popcount8((nibble >> 2) & 0x03) // bits 2-3
		out[i] = int32(a) - int32(b)
	}
	return out, nil
}

// sampleUniformUint32 samples a uniformly random uint32 in [0, q)
// using rejection sampling. No modular bias.
//
// We sample 4 random bytes and accept if the value is in
// [0, floor(2^32 / q) * q). This loop terminates in expected 1–2 iterations
// for typical values of q (e.g. q=12289 has acceptance rate >99.97%).
func sampleUniformUint32(q uint32) (uint32, error) {
	if q == 0 {
		return 0, errors.New("lwe: q must be non-zero")
	}
	// threshold = largest multiple of q that fits in uint32
	// = floor(2^32 / q) * q
	// Using 64-bit arithmetic to avoid overflow:
	threshold := uint32((^uint64(0) - uint64(q) + 1) % uint64(q))
	// threshold = 2^32 mod q (rejection boundary)

	var buf [4]byte
	for {
		if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
			return 0, errors.New("lwe: CSPRNG failure in uniform sampling: " + err.Error())
		}
		v := uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24
		// Reject values in the biased region
		if v >= threshold {
			return v % q, nil
		}
		// Rejected — loop (expected < 2 iterations)
	}
}

// popcount64 counts the number of set bits in a uint64 (Hamming weight).
// Uses the parallel bit-counting technique — no branches.
func popcount64(x uint64) uint32 {
	x = x - ((x >> 1) & 0x5555555555555555)
	x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333)
	x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f
	return uint32((x * 0x0101010101010101) >> 56)
}

// popcount8 counts the number of set bits in a byte.
func popcount8(x byte) uint32 {
	x = x - ((x >> 1) & 0x55)
	x = (x & 0x33) + ((x >> 2) & 0x33)
	x = (x + (x >> 4)) & 0x0f
	return uint32(x)
}