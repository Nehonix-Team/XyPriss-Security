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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// ─── Core Types ──────────────────────────────────────────────────────────────

// EncryptedPackage contains the ciphertext and metadata required for decryption.
type EncryptedPackage struct {
	Data      []byte    // Ciphertext (without auth tag)
	Nonce     []byte    // Nonce / IV
	AuthTag   []byte    // AEAD authentication tag
	Algorithm string    // Algorithm identifier (e.g. "AES-256-GCM")
	CreatedAt time.Time // Timestamp (informational)
}

// KeyPair holds an asymmetric key pair (PEM-encoded).
type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

// SealedEnvelope wraps a symmetric key encrypted with an asymmetric key,
// enabling hybrid encryption workflows.
type SealedEnvelope struct {
	EncryptedKey  []byte           // Symmetric key sealed with recipient's public key
	Package       *EncryptedPackage // Payload encrypted with the symmetric key
}

// ─── AES-256-GCM ─────────────────────────────────────────────────────────────

// EncryptAESGCM encrypts plaintext using AES-256-GCM with optional additional data (AAD).
func EncryptAESGCM(plaintext, key []byte, ad []byte) (*EncryptedPackage, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256-GCM: key must be exactly 32 bytes")
	}
	if len(plaintext) == 0 {
		return nil, errors.New("AES-256-GCM: plaintext must not be empty")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES-256-GCM: cipher init: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("AES-256-GCM: GCM init: %w", err)
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("AES-256-GCM: nonce generation: %w", err)
	}

	sealed := aesgcm.Seal(nil, nonce, plaintext, ad)
	tagSize := aesgcm.Overhead()

	return &EncryptedPackage{
		Data:      sealed[:len(sealed)-tagSize],
		Nonce:     nonce,
		AuthTag:   sealed[len(sealed)-tagSize:],
		Algorithm: "AES-256-GCM",
		CreatedAt: time.Now().UTC(),
	}, nil
}

// DecryptAESGCM decrypts an AES-256-GCM ciphertext and verifies the auth tag.
func DecryptAESGCM(ciphertext, key, nonce, tag, ad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256-GCM: key must be exactly 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES-256-GCM: cipher init: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("AES-256-GCM: GCM init: %w", err)
	}

	sealed := append(ciphertext, tag...)
	plaintext, err := aesgcm.Open(nil, nonce, sealed, ad)
	if err != nil {
		return nil, fmt.Errorf("AES-256-GCM: decryption/authentication failed: %w", err)
	}
	return plaintext, nil
}

// DecryptAESGCMPackage is a convenience wrapper that decrypts directly from an EncryptedPackage.
func DecryptAESGCMPackage(pkg *EncryptedPackage, key, ad []byte) ([]byte, error) {
	if pkg == nil {
		return nil, errors.New("AES-256-GCM: nil package")
	}
	return DecryptAESGCM(pkg.Data, key, pkg.Nonce, pkg.AuthTag, ad)
}

// ReEncryptAESGCM decrypts with oldKey and immediately re-encrypts with newKey (key rotation).
func ReEncryptAESGCM(pkg *EncryptedPackage, oldKey, newKey, ad []byte) (*EncryptedPackage, error) {
	plaintext, err := DecryptAESGCMPackage(pkg, oldKey, ad)
	if err != nil {
		return nil, fmt.Errorf("re-encrypt: %w", err)
	}
	return EncryptAESGCM(plaintext, newKey, ad)
}

// ─── ChaCha20-Poly1305 ───────────────────────────────────────────────────────

// EncryptChaCha20Poly1305 encrypts plaintext using ChaCha20-Poly1305 (preferred on mobile/ARM).
func EncryptChaCha20Poly1305(plaintext, key []byte, ad []byte) (*EncryptedPackage, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("ChaCha20-Poly1305: plaintext must not be empty")
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("ChaCha20-Poly1305: init: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("ChaCha20-Poly1305: nonce generation: %w", err)
	}

	sealed := aead.Seal(nil, nonce, plaintext, ad)
	tagSize := aead.Overhead()

	return &EncryptedPackage{
		Data:      sealed[:len(sealed)-tagSize],
		Nonce:     nonce,
		AuthTag:   sealed[len(sealed)-tagSize:],
		Algorithm: "ChaCha20-Poly1305",
		CreatedAt: time.Now().UTC(),
	}, nil
}

// DecryptChaCha20Poly1305 decrypts and authenticates a ChaCha20-Poly1305 ciphertext.
func DecryptChaCha20Poly1305(ciphertext, key, nonce, tag, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("ChaCha20-Poly1305: init: %w", err)
	}

	sealed := append(ciphertext, tag...)
	plaintext, err := aead.Open(nil, nonce, sealed, ad)
	if err != nil {
		return nil, fmt.Errorf("ChaCha20-Poly1305: decryption/authentication failed: %w", err)
	}
	return plaintext, nil
}

// DecryptChaCha20Poly1305Package is a convenience wrapper for EncryptedPackage.
func DecryptChaCha20Poly1305Package(pkg *EncryptedPackage, key, ad []byte) ([]byte, error) {
	if pkg == nil {
		return nil, errors.New("ChaCha20-Poly1305: nil package")
	}
	return DecryptChaCha20Poly1305(pkg.Data, key, pkg.Nonce, pkg.AuthTag, ad)
}

// EncryptXChaCha20Poly1305 uses XChaCha20-Poly1305 with a 192-bit nonce (safer for random nonces).
func EncryptXChaCha20Poly1305(plaintext, key []byte, ad []byte) (*EncryptedPackage, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("XChaCha20-Poly1305: plaintext must not be empty")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("XChaCha20-Poly1305: init: %w", err)
	}

	nonce := make([]byte, aead.NonceSize()) // 24 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("XChaCha20-Poly1305: nonce generation: %w", err)
	}

	sealed := aead.Seal(nil, nonce, plaintext, ad)
	tagSize := aead.Overhead()

	return &EncryptedPackage{
		Data:      sealed[:len(sealed)-tagSize],
		Nonce:     nonce,
		AuthTag:   sealed[len(sealed)-tagSize:],
		Algorithm: "XChaCha20-Poly1305",
		CreatedAt: time.Now().UTC(),
	}, nil
}

// DecryptXChaCha20Poly1305Package decrypts an XChaCha20-Poly1305 EncryptedPackage.
func DecryptXChaCha20Poly1305Package(pkg *EncryptedPackage, key, ad []byte) ([]byte, error) {
	if pkg == nil {
		return nil, errors.New("XChaCha20-Poly1305: nil package")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("XChaCha20-Poly1305: init: %w", err)
	}

	sealed := append(pkg.Data, pkg.AuthTag...)
	plaintext, err := aead.Open(nil, pkg.Nonce, sealed, ad)
	if err != nil {
		return nil, fmt.Errorf("XChaCha20-Poly1305: decryption/authentication failed: %w", err)
	}
	return plaintext, nil
}

// ─── AES-256-CTR (streaming, no auth – pair with HMAC) ───────────────────────

// EncryptAESCTR encrypts with AES-256-CTR. WARNING: provides confidentiality only.
// Always authenticate the output separately (e.g. with HMAC_SHA256).
func EncryptAESCTR(plaintext, key []byte) (ciphertext, iv []byte, err error) {
	if len(key) != 32 {
		return nil, nil, errors.New("AES-CTR: key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("AES-CTR: cipher init: %w", err)
	}

	iv = make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, fmt.Errorf("AES-CTR: IV generation: %w", err)
	}

	ciphertext = make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, iv, nil
}

// DecryptAESCTR decrypts an AES-256-CTR ciphertext.
func DecryptAESCTR(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES-CTR: cipher init: %w", err)
	}
	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

// ─── Hybrid Encryption (RSA-OAEP + AES-256-GCM) ─────────────────────────────

// GenerateRSAKeyPair generates a 4096-bit RSA key pair (PEM-encoded).
func GenerateRSAKeyPair() (*KeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("RSA keygen: %w", err)
	}

	privDER := x509.MarshalPKCS1PrivateKey(priv)
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("RSA pubkey marshal: %w", err)
	}

	return &KeyPair{
		PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER}),
		PublicKey:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}),
	}, nil
}

// HybridEncrypt generates a random AES-256 key, encrypts the plaintext with it,
// then seals the AES key under the recipient's RSA public key.
func HybridEncrypt(plaintext, rsaPublicKeyPEM, ad []byte) (*SealedEnvelope, error) {
	symKey, err := RandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("hybrid encrypt: symkey gen: %w", err)
	}

	pkg, err := EncryptAESGCM(plaintext, symKey, ad)
	if err != nil {
		return nil, fmt.Errorf("hybrid encrypt: payload: %w", err)
	}

	pub, err := parseRSAPublicKey(rsaPublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("hybrid encrypt: parse pubkey: %w", err)
	}

	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, symKey, nil)
	if err != nil {
		return nil, fmt.Errorf("hybrid encrypt: seal symkey: %w", err)
	}

	return &SealedEnvelope{EncryptedKey: encKey, Package: pkg}, nil
}

// HybridDecrypt recovers the symmetric key with the RSA private key, then decrypts the payload.
func HybridDecrypt(env *SealedEnvelope, rsaPrivateKeyPEM, ad []byte) ([]byte, error) {
	if env == nil {
		return nil, errors.New("hybrid decrypt: nil envelope")
	}

	priv, err := parseRSAPrivateKey(rsaPrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("hybrid decrypt: parse privkey: %w", err)
	}

	symKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, env.EncryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("hybrid decrypt: unseal symkey: %w", err)
	}

	return DecryptAESGCMPackage(env.Package, symKey, ad)
}

// ─── ECDH Key Exchange (Curve25519) ──────────────────────────────────────────

// GenerateX25519KeyPair generates an X25519 (Curve25519) ECDH key pair.
func GenerateX25519KeyPair() (publicKey, privateKey [32]byte, err error) {
	if _, err = io.ReadFull(rand.Reader, privateKey[:]); err != nil {
		return
	}
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return
}

// DeriveSharedSecretX25519 computes the X25519 shared secret from a private key and peer public key.
// The result should be passed through HKDF before use as a symmetric key.
func DeriveSharedSecretX25519(privateKey, peerPublicKey [32]byte) ([32]byte, error) {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &privateKey, &peerPublicKey)
	// All-zero output indicates an invalid peer key (small-order point).
	var zero [32]byte
	if shared == zero {
		return zero, errors.New("X25519: invalid peer public key (small-order point)")
	}
	return shared, nil
}

// ─── ECDH P-256 ──────────────────────────────────────────────────────────────

// GenerateP256KeyPair generates a NIST P-256 ECDH key pair.
func GenerateP256KeyPair() (*ecdh.PrivateKey, error) {
	return ecdh.P256().GenerateKey(rand.Reader)
}

// DeriveSharedSecretP256 computes the P-256 ECDH shared secret.
func DeriveSharedSecretP256(priv *ecdh.PrivateKey, peerPub *ecdh.PublicKey) ([]byte, error) {
	shared, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("P-256 ECDH: %w", err)
	}
	return shared, nil
}

// ─── Envelope Helpers ────────────────────────────────────────────────────────

// EncryptWithDerivedKey derives an AES-256 key via HKDF (from a shared secret or passphrase),
// then encrypts the payload. Useful for ECDH-based encryption.
func EncryptWithDerivedKey(plaintext, ikm, salt, info, ad []byte) (*EncryptedPackage, error) {
	key, err := HKDF(ikm, salt, info, 32)
	if err != nil {
		return nil, fmt.Errorf("encrypt with derived key: HKDF: %w", err)
	}
	return EncryptAESGCM(plaintext, key, ad)
}

// DecryptWithDerivedKey mirrors EncryptWithDerivedKey for decryption.
func DecryptWithDerivedKey(pkg *EncryptedPackage, ikm, salt, info, ad []byte) ([]byte, error) {
	key, err := HKDF(ikm, salt, info, 32)
	if err != nil {
		return nil, fmt.Errorf("decrypt with derived key: HKDF: %w", err)
	}
	return DecryptAESGCMPackage(pkg, key, ad)
}

// ─── Authenticated Encryption Helpers ────────────────────────────────────────

// Encrypt selects the best AEAD algorithm: XChaCha20-Poly1305 by default
// (longer nonce, safe for random generation at scale).
func Encrypt(plaintext, key, ad []byte) (*EncryptedPackage, error) {
	return EncryptXChaCha20Poly1305(plaintext, key, ad)
}

// Decrypt is the counterpart to Encrypt – dispatches based on pkg.Algorithm.
func Decrypt(pkg *EncryptedPackage, key, ad []byte) ([]byte, error) {
	if pkg == nil {
		return nil, errors.New("decrypt: nil package")
	}
	switch pkg.Algorithm {
	case "AES-256-GCM":
		return DecryptAESGCMPackage(pkg, key, ad)
	case "ChaCha20-Poly1305":
		return DecryptChaCha20Poly1305Package(pkg, key, ad)
	case "XChaCha20-Poly1305", "":
		return DecryptXChaCha20Poly1305Package(pkg, key, ad)
	default:
		return nil, fmt.Errorf("decrypt: unsupported algorithm %q", pkg.Algorithm)
	}
}

// ─── AES Key Wrap (RFC 3394) ─────────────────────────────────────────────────

// WrapKey encrypts a symmetric key (key data encryption key – KDEK pattern)
// using AES-256-GCM. Useful for key storage and transport.
func WrapKey(keyToWrap, wrappingKey []byte) (*EncryptedPackage, error) {
	if len(wrappingKey) != 32 {
		return nil, errors.New("WrapKey: wrapping key must be 32 bytes")
	}
	return EncryptAESGCM(keyToWrap, wrappingKey, []byte("key-wrap"))
}

// UnwrapKey decrypts a wrapped key.
func UnwrapKey(pkg *EncryptedPackage, wrappingKey []byte) ([]byte, error) {
	return DecryptAESGCMPackage(pkg, wrappingKey, []byte("key-wrap"))
}

// ─── Secure Wipe ─────────────────────────────────────────────────────────────

// SecureWipe overwrites a byte slice with zeros to minimise key material lingering in memory.
// Note: Go's GC may have already copied the slice; this is best-effort.
func SecureWipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ─── Internal Helpers ────────────────────────────────────────────────────────

func parseRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsaPub, nil
}

func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// ensure sha512 is used (for future hash helpers in this file)
var _ = sha512.New