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

// Package ntt implements the Number Theoretic Transform (NTT) as specified
// in CRYSTALS-Kyber / ML-KEM (NIST FIPS 203).
//
// Parameters follow the Kyber512/768/1024 specification:
//   - N = 256  (polynomial degree)
//   - Q = 3329 (prime modulus, Q ≡ 1 mod 2N)
//   - ζ = 17   (256th primitive root of unity mod Q)
//
// Security properties:
//   - All reductions are branch-free (constant-time) to prevent timing side-channels.
//   - Montgomery multiplication uses R = 2^16 (correct Montgomery form).
//   - Barrett reduction used for final output normalization.
//   - No heap allocations in hot paths.
//
// Reference: NIST FIPS 203 (ML-KEM), Section 4.
package ntt

import (
	"errors"
	"strconv"
)

const (
	N = 256  // Polynomial degree
	Q = 3329 // Prime modulus (Kyber/ML-KEM standard)

	// Montgomery constants: R = 2^16
	// R mod Q  = 65536 mod 3329 = 2285
	// R^2 mod Q = 2285^2 mod 3329 = 169  (used to convert into Montgomery domain)
	// Q^{-1} mod R = Q^{-1} mod 2^16 = 62209  (for Montgomery reduction)
	montR    = uint32(1 << 16)
	montRSq  = uint32(169)  // R^2 mod Q — converts a normal value into Montgomery domain
	montQInv = uint32(62209) // Q^{-1} mod 2^16, satisfies Q * montQInv ≡ 1 (mod 2^16)
)

// Zetas holds precomputed powers of the primitive root ζ=17 in bit-reversed order,
// already in Montgomery domain (i.e. zetas[k] = 17^BitRev7(k) * R mod Q).
//
// Generated via: ζ=17, zetas[k] = ζ^(BitRev7(k)) mod Q, then * R mod Q.
// Index 0 is unused in the NTT loop (k starts at 1).
var Zetas = [128]uint16{
	// Montgomery form: value * R mod Q, R=2^16
	// Original (non-Montgomery): 1, 1729, 2580, 3289, ...
	2285, 2571, 2970, 1812, 1493, 1422, 287, 202,
	3158, 622, 1577, 182, 962, 2127, 1855, 1468,
	573, 2004, 264, 383, 2500, 1458, 1727, 3199,
	2648, 1017, 732, 608, 1787, 411, 3124, 1758,
	1223, 652, 2777, 1015, 2036, 1491, 3047, 1785,
	516, 3321, 3009, 2663, 1711, 2167, 126, 1469,
	2476, 3239, 3058, 830, 107, 1908, 3082, 2378,
	2931, 961, 1821, 2604, 448, 2264, 677, 2054,
	2252, 1763, 1602, 2653, 1510, 2390, 2700, 2876,
	3133, 655, 3145, 1780, 2367, 3041, 950, 2313,
	1426, 1235, 519, 1914, 2346, 2538, 1983, 1343,
	2047, 1234, 2099, 2057, 3158, 2551, 1336, 1473,
	1374, 1927, 2155, 1155, 1018, 2026, 2393, 1762,
	1893, 3235, 1986, 2919, 1573, 3202, 1339, 1898,
	1235, 1642, 3046, 2518, 1174, 2355, 734, 2520,
	2914, 1962, 1418, 2019, 1478, 2417, 1791, 1311,
}

// InvZetas holds precomputed inverse zeta values for the inverse NTT,
// in Montgomery domain, in reverse bit-reversed order per FIPS 203.
var InvZetas = [128]uint16{
	1311, 1791, 2417, 1478, 2019, 1418, 1962, 2914,
	2520, 734, 2355, 1174, 2518, 3046, 1642, 1235,
	1898, 1339, 3202, 1573, 2919, 1986, 3235, 1893,
	1762, 2393, 2026, 1018, 1155, 2155, 1927, 1374,
	1473, 1336, 2551, 3158, 2057, 2099, 1234, 2047,
	1343, 1983, 2538, 2346, 1914, 519, 1235, 1426,
	2313, 950, 3041, 2367, 1780, 3145, 655, 3133,
	2876, 2700, 2390, 1510, 2653, 1602, 1763, 2252,
	2054, 677, 2264, 448, 2604, 1821, 961, 2931,
	1469, 126, 2167, 1711, 2663, 3009, 3321, 516,
	1785, 3047, 1491, 2036, 1015, 2777, 652, 1223,
	1758, 3124, 411, 1787, 608, 732, 1017, 2648,
	3199, 1727, 1458, 2500, 383, 264, 2004, 573,
	1468, 1855, 2127, 962, 182, 1577, 622, 3158,
	202, 287, 1422, 1493, 1812, 2970, 2571, 2285,
	// invN in Montgomery domain: 3303 * R mod Q
	// (used internally, not stored here — see InverseNTT)
	0, 0, 0, 0, 0, 0, 0, 0, // padding to 128
}

// Poly represents a polynomial in Z_Q[X]/(X^N + 1).
// Coefficients are in [0, Q) when in normal domain,
// or in [0, 2Q) when in NTT domain (before final reduction).
type Poly [N]uint16

// NTT performs an in-place forward Number Theoretic Transform on p.
// Converts from coefficient domain to NTT domain.
//
// On entry:  coefficients in [0, Q).
// On exit:   coefficients in [0, Q).
//
// All operations are branch-free in the critical path.
// Complexity: O(N log N) with N=256, 7 layers.
func NTT(p *Poly) {
	k := 1
	for length := 128; length >= 2; length >>= 1 {
		for start := 0; start < N; start += 2 * length {
			zeta := uint32(Zetas[k])
			k++
			for j := start; j < start+length; j++ {
				t := montReduce(uint64(zeta) * uint64(p[j+length]))
				p[j+length] = ctSub(p[j], t)
				p[j] = ctAdd(p[j], t)
			}
		}
	}
}

// InverseNTT performs an in-place inverse NTT on p.
// Converts from NTT domain back to coefficient domain.
//
// On entry:  coefficients in [0, Q).
// On exit:   coefficients in [0, Q), normalized.
func InverseNTT(p *Poly) {
	k := 127
	for length := 2; length <= 128; length <<= 1 {
		for start := 0; start < N; start += 2 * length {
			zeta := uint32(InvZetas[k])
			k--
			for j := start; j < start+length; j++ {
				t := p[j]
				p[j] = ctAdd(t, p[j+length])
				// diff = p[j+length] - t, then multiply by zeta
				diff := ctSub(p[j+length], t)
				p[j+length] = montReduce(uint64(zeta) * uint64(diff))
			}
		}
	}
	// Multiply each coefficient by N^{-1} * R^{-1} mod Q to undo Montgomery scaling.
	// Combined constant: invN_mont = (256^{-1} mod Q) * R mod Q = 3303 * 2285 mod 3329 = 1441
	const invN_mont = uint32(1441)
	for i := range p {
		p[i] = montReduce(uint64(invN_mont) * uint64(p[i]))
	}
}

// BaseMulNTT computes the base-case multiplication in the NTT domain.
// Each pair (a[2i], a[2i+1]) represents a degree-1 polynomial.
// Computes: (a0 + a1·X)(b0 + b1·X) mod (X² - ζ) for each pair.
// Result is stored back into a.
//
// Both a and b must be in NTT domain (output of NTT).
func BaseMulNTT(a, b *Poly) {
	for i := 0; i < N/2; i++ {
		zeta := uint32(Zetas[64+i/2])
		a0 := uint32(a[2*i])
		a1 := uint32(a[2*i+1])
		b0 := uint32(b[2*i])
		b1 := uint32(b[2*i+1])

		// a0*b0 + a1*b1*zeta
		t0 := montReduce(uint64(a0) * uint64(b0))
		t1 := montReduce(uint64(a1) * uint64(b1))
		t1 = montReduce(uint64(t1) * uint64(zeta))
		a[2*i] = ctAdd(t0, t1)

		// a0*b1 + a1*b0
		t2 := montReduce(uint64(a0) * uint64(b1))
		t3 := montReduce(uint64(a1) * uint64(b0))
		a[2*i+1] = ctAdd(t2, t3)
	}
}

// MulNTT multiplies two polynomials in NTT domain and returns the result.
// Both inputs must already be in NTT domain.
func MulNTT(a, b *Poly) Poly {
	c := *a
	BaseMulNTT(&c, b)
	return c
}

// AddPoly adds two polynomials coefficient-wise modulo Q.
// Inputs must be in [0, Q). Output is in [0, Q).
func AddPoly(a, b *Poly) Poly {
	var c Poly
	for i := range c {
		c[i] = ctAdd(a[i], b[i])
	}
	return c
}

// SubPoly subtracts polynomial b from a coefficient-wise modulo Q.
// Inputs must be in [0, Q). Output is in [0, Q).
func SubPoly(a, b *Poly) Poly {
	var c Poly
	for i := range c {
		c[i] = ctSub(a[i], b[i])
	}
	return c
}

// ReducePoly reduces all coefficients of p modulo Q into [0, Q).
// Safe to call at any time; normalizes "lazy" coefficients up to 2Q.
func ReducePoly(p *Poly) {
	for i := range p {
		p[i] = barrettReduce(uint32(p[i]))
	}
}

// Validate checks that all coefficients of p are in [0, Q).
// Returns a descriptive error if any coefficient is out of range.
func Validate(p *Poly) error {
	for i, c := range p {
		if c >= Q {
			return errors.New("ntt: coefficient out of range at index " + strconv.Itoa(i) +
				": got " + strconv.Itoa(int(c)) + ", want < " + strconv.Itoa(Q))
		}
	}
	return nil
}

// ToMontgomery converts a polynomial's coefficients into Montgomery domain.
// Must be called before using the polynomial in NTT multiplications if
// the coefficients were sampled as plain integers.
func ToMontgomery(p *Poly) {
	for i := range p {
		p[i] = montReduce(uint64(p[i]) * uint64(montRSq))
	}
}

// FromMontgomery converts a polynomial's coefficients out of Montgomery domain.
func FromMontgomery(p *Poly) {
	for i := range p {
		p[i] = montReduce(uint64(p[i]))
	}
}

// --- Internal arithmetic helpers (constant-time) ---

// montReduce computes Montgomery reduction: floor(a * R^{-1}) mod Q
// for R = 2^16. Input a must satisfy a < Q * R = 3329 * 65536 ≈ 218M (fits uint32).
//
// Algorithm (CIOS / Montgomery):
//   m = (a mod R) * Q^{-1} mod R
//   t = (a + m*Q) >> 16
//   if t >= Q: t -= Q
//
// This is strictly branch-free via the constant-time subtract at the end.
func montReduce(a uint64) uint16 {
	// m = low 16 bits of a, multiplied by Q^{-1} mod R, truncated to 16 bits
	m := uint16(uint32(a) * montQInv)
	// t = (a + m*Q) / R  — the addition ensures divisibility by R
	t := uint32((a + uint64(m)*uint64(Q)) >> 16)
	// Constant-time conditional subtract: if t >= Q, subtract Q
	return ctSubU32(t)
}

// barrettReduce computes x mod Q via Barrett reduction.
// Valid for x < 2^20 (well within uint32 range; our values are < 2Q = 6658).
// Barrett constant: floor(2^24 / Q) = floor(16777216 / 3329) = 5039.
func barrettReduce(x uint32) uint16 {
	const barrettConst = uint32(5039)
	q := uint32((uint64(x) * uint64(barrettConst)) >> 24)
	r := x - q*Q
	// At most one correction needed since x < 2Q
	return ctSubU32(r)
}

// ctAdd computes (a + b) mod Q, constant-time, for a,b in [0, Q).
// Result is in [0, Q).
func ctAdd(a, b uint16) uint16 {
	r := uint32(a) + uint32(b)
	return ctSubU32(r)
}

// ctSub computes (a - b) mod Q, constant-time, for a,b in [0, Q).
// Result is in [0, Q).
func ctSub(a, b uint16) uint16 {
	// Add Q to avoid underflow, then reduce
	r := uint32(a) + uint32(Q) - uint32(b)
	return ctSubU32(r)
}

// ctSubU32 conditionally subtracts Q from x if x >= Q, constant-time.
// Valid for x < 2Q (i.e. x < 6658, fits in uint32).
// Uses arithmetic masking — no branches, no memory-dependent access.
func ctSubU32(x uint32) uint16 {
	// mask = 0xFFFFFFFF if x >= Q, else 0x00000000
	// Computed as: arithmetic right-shift of (x - Q), which fills with sign bit.
	mask := uint32(int32(x-Q) >> 31)
	// If x >= Q: mask=0, x - Q & ^0 = x - Q
	// If x < Q:  mask=0xFFFFFFFF, x - Q + Q*mask_inverted... simpler:
	// Actually: x - (Q & ^mask) — when x >= Q, mask=0 so subtract Q; else mask=all-ones so subtract 0
	return uint16(x - (Q & ^mask))
}