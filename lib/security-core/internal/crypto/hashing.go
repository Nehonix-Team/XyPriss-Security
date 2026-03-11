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

package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

// ─── Hash Functions ───────────────────────────────────────────────────────────

// SHA256 returns the SHA-256 digest of data.
func SHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// SHA256Hex returns the hex-encoded SHA-256 digest of data.
func SHA256Hex(data []byte) string {
	return hex.EncodeToString(SHA256(data))
}

// SHA512 returns the SHA-512 digest of data.
func SHA512(data []byte) []byte {
	h := sha512.Sum512(data)
	return h[:]
}

// SHA512Hex returns the hex-encoded SHA-512 digest of data.
func SHA512Hex(data []byte) string {
	return hex.EncodeToString(SHA512(data))
}

// SHA3_256 returns the SHA3-256 (Keccak) digest of data.
func SHA3_256(data []byte) []byte {
	h := sha3.Sum256(data)
	return h[:]
}

// SHA3_512 returns the SHA3-512 (Keccak) digest of data.
func SHA3_512(data []byte) []byte {
	h := sha3.Sum512(data)
	return h[:]
}

// SHAKE128 returns a variable-length SHAKE128 digest of outputLen bytes.
func SHAKE128(data []byte, outputLen int) []byte {
	out := make([]byte, outputLen)
	sha3.ShakeSum128(out, data)
	return out
}

// SHAKE256 returns a variable-length SHAKE256 digest of outputLen bytes.
func SHAKE256(data []byte, outputLen int) []byte {
	out := make([]byte, outputLen)
	sha3.ShakeSum256(out, data)
	return out
}

// Blake2b256 returns the BLAKE2b-256 digest (faster than SHA-256 in software).
func Blake2b256(data []byte) ([]byte, error) {
	h, err := blake2b.New256(nil)
	if err != nil {
		return nil, fmt.Errorf("BLAKE2b-256: %w", err)
	}
	h.Write(data)
	return h.Sum(nil), nil
}

// Blake2b512 returns the BLAKE2b-512 digest.
func Blake2b512(data []byte) ([]byte, error) {
	h, err := blake2b.New512(nil)
	if err != nil {
		return nil, fmt.Errorf("BLAKE2b-512: %w", err)
	}
	h.Write(data)
	return h.Sum(nil), nil
}

// Blake2s256 returns the BLAKE2s-256 digest (optimised for 32-bit / IoT).
func Blake2s256(data []byte) ([]byte, error) {
	h, err := blake2s.New256(nil)
	if err != nil {
		return nil, fmt.Errorf("BLAKE2s-256: %w", err)
	}
	h.Write(data)
	return h.Sum(nil), nil
}

// ─── MAC / HMAC ──────────────────────────────────────────────────────────────

// HMAC_SHA256 computes HMAC-SHA256 of data with key.
func HMAC_SHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// HMAC_SHA512 computes HMAC-SHA512 of data with key.
func HMAC_SHA512(key, data []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// HMAC_SHA256Hex returns the hex-encoded HMAC-SHA256.
func HMAC_SHA256Hex(key, data []byte) string {
	return hex.EncodeToString(HMAC_SHA256(key, data))
}

// VerifyHMAC_SHA256 does a constant-time comparison of the expected tag.
func VerifyHMAC_SHA256(key, data, tag []byte) bool {
	expected := HMAC_SHA256(key, data)
	return subtle.ConstantTimeCompare(expected, tag) == 1
}

// Blake2bMAC computes a keyed BLAKE2b-256 MAC (key must be 1-32 bytes).
func Blake2bMAC(key, data []byte) ([]byte, error) {
	if len(key) == 0 || len(key) > 32 {
		return nil, errors.New("BLAKE2b-MAC: key must be 1-32 bytes")
	}
	h, err := blake2b.New256(key)
	if err != nil {
		return nil, fmt.Errorf("BLAKE2b-MAC: %w", err)
	}
	h.Write(data)
	return h.Sum(nil), nil
}

// ─── Key Derivation Functions ────────────────────────────────────────────────

// HKDF derives outputLen bytes from ikm (Input Key Material) using SHA-256.
func HKDF(ikm, salt, info []byte, outputLen int) ([]byte, error) {
	if outputLen <= 0 {
		return nil, errors.New("HKDF: outputLen must be > 0")
	}
	r := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, outputLen)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("HKDF: %w", err)
	}
	return out, nil
}

// HKDFExtract performs the HKDF Extract step (PRK = HMAC-Hash(salt, IKM)).
func HKDFExtract(ikm, salt []byte) []byte {
	return HMAC_SHA256(salt, ikm)
}

// HKDFExpand performs the HKDF Expand step from a PRK.
func HKDFExpand(prk, info []byte, outputLen int) ([]byte, error) {
	return HKDF(prk, nil, info, outputLen)
}

// ─── Password Hashing ────────────────────────────────────────────────────────

// Argon2idParams holds the tuning parameters for Argon2id.
type Argon2idParams struct {
	Memory      uint32 // KiB, default 64 MiB
	Iterations  uint32 // default 3
	Parallelism uint8  // default 4
	KeyLen      uint32 // output key length, default 32
	SaltLen     int    // salt length, default 16
}

// DefaultArgon2idParams returns safe production defaults (OWASP recommendation).
func DefaultArgon2idParams() Argon2idParams {
	return Argon2idParams{
		Memory:      64 * 1024, // 64 MiB
		Iterations:  3,
		Parallelism: 4,
		KeyLen:      32,
		SaltLen:     16,
	}
}

// HashPasswordArgon2id hashes a password with Argon2id and returns a storable encoded string.
// Format: $argon2id$v=19$m=<m>,t=<t>,p=<p>$<salt_hex>$<hash_hex>
func HashPasswordArgon2id(password []byte, p Argon2idParams) (string, error) {
	salt, err := RandomBytes(p.SaltLen)
	if err != nil {
		return "", fmt.Errorf("argon2id: salt gen: %w", err)
	}

	hash := argon2.IDKey(password, salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLen)

	encoded := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		p.Memory, p.Iterations, p.Parallelism,
		hex.EncodeToString(salt),
		hex.EncodeToString(hash),
	)
	return encoded, nil
}

// VerifyPasswordArgon2id verifies a password against a stored Argon2id hash (constant-time).
func VerifyPasswordArgon2id(password []byte, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("argon2id: invalid encoded hash format")
	}

	var m, t uint32
	var pp uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &pp)
	if err != nil {
		return false, fmt.Errorf("argon2id: parse params: %w", err)
	}

	salt, err := hex.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("argon2id: decode salt: %w", err)
	}

	storedHash, err := hex.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("argon2id: decode hash: %w", err)
	}

	candidate := argon2.IDKey(password, salt, t, m, pp, uint32(len(storedHash)))
	return subtle.ConstantTimeCompare(candidate, storedHash) == 1, nil
}

// ScryptParams holds the tuning parameters for scrypt.
type ScryptParams struct {
	N       int // CPU/memory cost, must be power of 2
	R       int // block size
	P       int // parallelisation factor
	KeyLen  int // output key length
	SaltLen int // salt length
}

// DefaultScryptParams returns safe production defaults.
func DefaultScryptParams() ScryptParams {
	return ScryptParams{N: 32768, R: 8, P: 1, KeyLen: 32, SaltLen: 16}
}

// DeriveKeyScrypt derives a key from a password using scrypt.
func DeriveKeyScrypt(password []byte, p ScryptParams) (key, salt []byte, err error) {
	salt, err = RandomBytes(p.SaltLen)
	if err != nil {
		return nil, nil, fmt.Errorf("scrypt: salt gen: %w", err)
	}
	key, err = scrypt.Key(password, salt, p.N, p.R, p.P, p.KeyLen)
	if err != nil {
		return nil, nil, fmt.Errorf("scrypt: %w", err)
	}
	return key, salt, nil
}

// VerifyScrypt verifies a password against a previously derived key and salt.
func VerifyScrypt(password, storedKey, salt []byte, p ScryptParams) (bool, error) {
	candidate, err := scrypt.Key(password, salt, p.N, p.R, p.P, p.KeyLen)
	if err != nil {
		return false, fmt.Errorf("scrypt verify: %w", err)
	}
	return subtle.ConstantTimeCompare(candidate, storedKey) == 1, nil
}

// PBKDF2SHA256 derives a key from a password using PBKDF2-HMAC-SHA256.
// iterations=310000 is the OWASP minimum for SHA-256.
func PBKDF2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)
}

// PBKDF2SHA512 derives a key from a password using PBKDF2-HMAC-SHA512.
func PBKDF2SHA512(password, salt []byte, iterations, keyLen int) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLen, sha512.New)
}

// HashPasswordBcrypt hashes a password using bcrypt at the given cost (default: 12).
func HashPasswordBcrypt(password []byte, cost int) (string, error) {
	if cost < bcrypt.MinCost {
		cost = bcrypt.DefaultCost
	}
	hash, err := bcrypt.GenerateFromPassword(password, cost)
	if err != nil {
		return "", fmt.Errorf("bcrypt: %w", err)
	}
	return string(hash), nil
}

// VerifyPasswordBcrypt compares a bcrypt hash against a plaintext password (constant-time).
func VerifyPasswordBcrypt(password []byte, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), password) == nil
}

// ─── Random ───────────────────────────────────────────────────────────────────

// RandomBytes returns n cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("RandomBytes: n must be > 0")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("RandomBytes: %w", err)
	}
	return b, nil
}

// RandomHex returns n random bytes as a hex string (2n characters).
func RandomHex(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RandomInt63 returns a cryptographically secure random int64 in [0, max).
func RandomInt63(max int64) (int64, error) {
	if max <= 0 {
		return 0, errors.New("RandomInt63: max must be > 0")
	}
	b, err := RandomBytes(8)
	if err != nil {
		return 0, err
	}
	var n int64
	for i, v := range b {
		n |= int64(v) << (i * 8)
	}
	if n < 0 {
		n = -n
	}
	return n % max, nil
}

// NewSalt generates a random salt of the given length (recommended: 16 or 32 bytes).
func NewSalt(length int) ([]byte, error) {
	return RandomBytes(length)
}

// ─── Comparison ──────────────────────────────────────────────────────────────

// ConstantTimeEqual compares two byte slices in constant time, preventing timing attacks.
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ─── Token / OTP Helpers ─────────────────────────────────────────────────────

// GenerateToken produces a URL-safe random token of tokenBytes raw bytes (hex-encoded).
func GenerateToken(tokenBytes int) (string, error) {
	return RandomHex(tokenBytes)
}

// GenerateOTP returns a numeric OTP of digitCount digits (4-8 recommended).
func GenerateOTP(digitCount int) (string, error) {
	if digitCount < 4 || digitCount > 10 {
		return "", errors.New("GenerateOTP: digitCount must be 4-10")
	}
	max := int64(1)
	for i := 0; i < digitCount; i++ {
		max *= 10
	}
	n, err := RandomInt63(max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*s", digitCount, strconv.FormatInt(n, 10)), nil
}

// ─── Integrity Helpers ────────────────────────────────────────────────────────

// SignPayload produces a detached HMAC-SHA256 signature (hex) over payload + timestamp.
// The timestamp is embedded to allow expiry checks.
func SignPayload(payload, key []byte) (sig string, ts int64) {
	ts = time.Now().Unix()
	msg := append(payload, []byte(fmt.Sprintf("|ts=%d", ts))...)
	return HMAC_SHA256Hex(key, msg), ts
}

// VerifyPayload verifies a signed payload within maxAgeSeconds.
func VerifyPayload(payload, key []byte, sig string, ts int64, maxAgeSeconds int64) error {
	age := time.Now().Unix() - ts
	if age < 0 || age > maxAgeSeconds {
		return fmt.Errorf("VerifyPayload: timestamp expired (age=%ds, max=%ds)", age, maxAgeSeconds)
	}
	msg := append(payload, []byte(fmt.Sprintf("|ts=%d", ts))...)
	expected := HMAC_SHA256Hex(key, msg)
	if !ConstantTimeEqual([]byte(sig), []byte(expected)) {
		return errors.New("VerifyPayload: signature mismatch")
	}
	return nil
}

// ─── Fingerprinting ──────────────────────────────────────────────────────────

// Fingerprint returns a short (8-byte hex, 16 chars) SHA-256 fingerprint of data.
// Useful for non-secret identifiers (key IDs, content IDs).
func Fingerprint(data []byte) string {
	h := SHA256(data)
	return hex.EncodeToString(h[:8])
}

// PublicKeyFingerprint returns a 32-char hex fingerprint of a public key (or any blob).
func PublicKeyFingerprint(pubKey []byte) string {
	h := SHA256(pubKey)
	return hex.EncodeToString(h[:16])
}