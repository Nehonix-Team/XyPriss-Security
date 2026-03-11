package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"unsafe"

	"github.com/nehonix/xypriss-security-core/internal/crypto"
	"github.com/nehonix/xypriss-security-core/internal/engine"
	"github.com/nehonix/xypriss-security-core/internal/password"
	"github.com/nehonix/xypriss-security-core/internal/quantum/kyber"
	"github.com/nehonix/xypriss-security-core/internal/quantum/lwe"
	"github.com/nehonix/xypriss-security-core/internal/quantum/ntt"
	"golang.org/x/crypto/argon2"
)

/**
 * XyPriss Security Core - Ultra Robust Production Bridge
 */

// --- ENGINE ---

var globalEngine *engine.Engine

//export InitializeEngine
func InitializeEngine(workers C.int) {
	globalEngine = engine.NewEngine(int(workers))
	globalEngine.Start()
}

// --- PASSWORDS ---

//export HashPassword
func HashPassword(pass *C.char, algo *C.char, iterations C.int, memory C.int, parallelism C.int) *C.char {
	p := C.GoString(pass)
	a := C.GoString(algo)
	var hash string
	var err error

	switch a {
	case "scrypt":
		// Scrypt params could also be added, but for now fixed production defaults
		hash, err = password.HashScrypt(p)
	case "pbkdf2":
		hash, err = password.HashPBKDF2(p, int(iterations))
	case "argon2id":
		params := password.DefaultArgon2
		if iterations > 0 {
			params.Time = uint32(iterations)
		}
		if memory > 0 {
			params.Memory = uint32(memory)
		}
		if parallelism > 0 {
			params.Threads = uint8(parallelism)
		}
		
		salt, _ := crypto.RandomBytes(16)
		h := argon2.IDKey([]byte(p), salt, params.Time, params.Memory, params.Threads, params.KeyLen)
		
		b64Salt := base64.RawStdEncoding.EncodeToString(salt)
		b64Hash := base64.RawStdEncoding.EncodeToString(h)
		pStr := fmt.Sprintf("v=%d,m=%d,t=%d,p=%d", argon2.Version, params.Memory, params.Time, params.Threads)
		hash = fmt.Sprintf("$xypriss$argon2id$%s$%s$%s", pStr, b64Salt, b64Hash)
	default:
		hash, err = password.HashArgon2id(p)
	}


	if err != nil {
		return C.CString("error: " + err.Error())
	}
	return C.CString(hash)
}


//export VerifyPassword
func VerifyPassword(pass *C.char, hashEncoded *C.char) C.int {
	p := C.GoString(pass)
	h := C.GoString(hashEncoded)
	if password.Verify(p, h) {
		return 1
	}
	return 0
}

//export GeneratePassword
func GeneratePassword(length C.int, charset *C.char) *C.char {
	c := C.GoString(charset)
	p := password.Generate(int(length), c)
	return C.CString(p)
}


//export GetRandomBytes
func GetRandomBytes(length C.int) *C.char {
	b, err := crypto.RandomBytes(int(length))
	if err != nil {
		return C.CString("error: " + err.Error())
	}
	return C.CString(hex.EncodeToString(b))
}

//export GetRandomInt
func GetRandomInt(max C.long) C.long {
	val, err := crypto.RandomInt63(int64(max))
	if err != nil {
		return -1
	}
	return C.long(val)
}


//export GenerateOTP
func GenerateOTP(digitCount C.int) *C.char {
	otp, err := crypto.GenerateOTP(int(digitCount))
	if err != nil {
		return C.CString("error: " + err.Error())
	}
	return C.CString(otp)
}


// --- STANDALONE CRYPTO (REPLACING EXTERNAL JS CRYPTO) ---

//export GetHash
func GetHash(data *C.char, length C.int, algo *C.char) *C.char {
	b := C.GoBytes(unsafe.Pointer(data), length)
	a := strings.ToLower(C.GoString(algo))

	var h []byte
	var err error

	switch a {
	case "sha512":
		h = crypto.SHA512(b)
	case "sha3-256":
		h = crypto.SHA3_256(b)
	case "blake2b":
		h, err = crypto.Blake2b256(b)
	default:
		h = crypto.SHA256(b)
	}

	if err != nil {
		return C.CString("error: " + err.Error())
	}
	return C.CString(hex.EncodeToString(h))
}

//export GetSHA256
func GetSHA256(data *C.char, length C.int) *C.char {
	return GetHash(data, length, C.CString("sha256"))
}

//export GetHMAC
func GetHMAC(key *C.char, keyLen C.int, data *C.char, dataLen C.int, algo *C.char) *C.char {
	k := C.GoBytes(unsafe.Pointer(key), keyLen)
	d := C.GoBytes(unsafe.Pointer(data), dataLen)
	a := strings.ToLower(C.GoString(algo))

	var h []byte
	var err error

	switch a {
	case "sha512":
		h = crypto.HMAC_SHA512(k, d)
	case "blake2b":
		h, err = crypto.Blake2bMAC(k, d)
	default:
		h = crypto.HMAC_SHA256(k, d)
	}

	if err != nil {
		return C.CString("error: " + err.Error())
	}
	return C.CString(hex.EncodeToString(h))
}

//export HKDF
func HKDF(ikm *C.char, ikmLen C.int, salt *C.char, saltLen C.int, info *C.char, infoLen C.int, outputLen C.int) *C.char {
	ikmB := C.GoBytes(unsafe.Pointer(ikm), ikmLen)
	saltB := C.GoBytes(unsafe.Pointer(salt), saltLen)
	infoB := C.GoBytes(unsafe.Pointer(info), infoLen)

	out, err := crypto.HKDF(ikmB, saltB, infoB, int(outputLen))
	if err != nil {
		return C.CString("error: " + err.Error())
	}
	return C.CString(hex.EncodeToString(out))
}

//export PBKDF2
func PBKDF2(pass *C.char, salt *C.char, saltLen C.int, iterations C.int, keyLen C.int, algo *C.char) *C.char {
	p := []byte(C.GoString(pass))
	s := C.GoBytes(unsafe.Pointer(salt), saltLen)
	a := strings.ToLower(C.GoString(algo))

	var h []byte
	if a == "sha512" {
		h = crypto.PBKDF2SHA512(p, s, int(iterations), int(keyLen))
	} else {
		h = crypto.PBKDF2SHA256(p, s, int(iterations), int(keyLen))
	}

	return C.CString(hex.EncodeToString(h))
}

//export ConstantTimeCompare
func ConstantTimeCompare(a *C.char, aLen C.int, b *C.char, bLen C.int) C.int {
	aB := C.GoBytes(unsafe.Pointer(a), aLen)
	bB := C.GoBytes(unsafe.Pointer(b), bLen)
	if crypto.ConstantTimeEqual(aB, bB) {
		return 1
	}
	return 0
}


//export Encrypt
func Encrypt(pass *C.char, key *C.char, algo *C.char) *C.char {
	plaintext := []byte(C.GoString(pass))
	keyBytes, _ := hex.DecodeString(C.GoString(key))
	a := C.GoString(algo)

	var pkg *crypto.EncryptedPackage
	var err error

	if a == "chacha20" {
		pkg, err = crypto.EncryptChaCha20Poly1305(plaintext, keyBytes, nil)
	} else {
		pkg, err = crypto.EncryptAESGCM(plaintext, keyBytes, nil)
	}

	if err != nil {
		return C.CString("error: " + err.Error())
	}

	return C.CString(fmt.Sprintf("%s:%s:%s", hex.EncodeToString(pkg.Nonce), hex.EncodeToString(pkg.AuthTag), hex.EncodeToString(pkg.Data)))
}

//export Decrypt
func Decrypt(encrypted *C.char, key *C.char, algo *C.char) *C.char {
	parts := C.GoString(encrypted)
	keyBytes, _ := hex.DecodeString(C.GoString(key))
	a := C.GoString(algo)

	meta := strings.Split(parts, ":")
	if len(meta) != 3 {
		return C.CString("error: invalid format")
	}
	nonce, _ := hex.DecodeString(meta[0])
	tag, _ := hex.DecodeString(meta[1])
	data, _ := hex.DecodeString(meta[2])

	var dec []byte
	var err error
	if a == "chacha20" {
		dec, err = crypto.DecryptChaCha20Poly1305(data, keyBytes, nonce, tag, nil)
	} else {
		dec, err = crypto.DecryptAESGCM(data, keyBytes, nonce, tag, nil)
	}

	if err != nil {
		return C.CString("error: " + err.Error())
	}
	return C.CString(string(dec))
}

// EncryptRaw encrypts raw binary data with a raw binary key (no hex encoding needed).
// Returns nonce:authTag:ciphertext as hex, or "error: ..." on failure.

//export EncryptRaw
func EncryptRaw(data *C.char, dataLen C.int, key *C.char, keyLen C.int, algo *C.char) *C.char {
	d := C.GoBytes(unsafe.Pointer(data), dataLen)
	k := C.GoBytes(unsafe.Pointer(key), keyLen)
	a := C.GoString(algo)

	var pkg *crypto.EncryptedPackage
	var err error

	if a == "chacha20" {
		pkg, err = crypto.EncryptChaCha20Poly1305(d, k, nil)
	} else {
		pkg, err = crypto.EncryptAESGCM(d, k, nil)
	}

	if err != nil {
		return C.CString("error: " + err.Error())
	}
	return C.CString(fmt.Sprintf("%s:%s:%s",
		hex.EncodeToString(pkg.Nonce),
		hex.EncodeToString(pkg.AuthTag),
		hex.EncodeToString(pkg.Data),
	))
}

// DecryptRaw decrypts raw binary data using nonce:authTag:ciphertext hex format.

//export DecryptRaw
func DecryptRaw(encrypted *C.char, key *C.char, algo *C.char, keyLen C.int) *C.char {
	parts := C.GoString(encrypted)
	a := C.GoString(algo)
	k := C.GoBytes(unsafe.Pointer(key), keyLen)

	meta := strings.Split(parts, ":")
	if len(meta) != 3 {
		return C.CString("error: invalid format")
	}
	nonce, _ := hex.DecodeString(meta[0])
	tag, _ := hex.DecodeString(meta[1])
	data, _ := hex.DecodeString(meta[2])

	var dec []byte
	var err error
	if a == "chacha20" {
		dec, err = crypto.DecryptChaCha20Poly1305(data, k, nonce, tag, nil)
	} else {
		dec, err = crypto.DecryptAESGCM(data, k, nonce, tag, nil)
	}

	if err != nil {
		return C.CString("error: " + err.Error())
	}
	return C.CString(hex.EncodeToString(dec))
}

// --- QUANTUM EXTRAS (NTT/LWE) ---

//export RunNTT
func RunNTT(data *C.char) {
	p := (*ntt.Poly)(unsafe.Pointer(data))
	ntt.NTT(p)
}

//export SampleLWEError
func SampleLWEError() C.int {
	val, _ := lwe.SampleCBD(2)
	return C.int(val)
}

//export KyberGenerateKeyPair
func KyberGenerateKeyPair() *C.char {
	kp, err := kyber.GenerateKeyPair()
	if err != nil {
		return C.CString("error: " + err.Error())
	}
	return C.CString(fmt.Sprintf("%s:%s", base64.StdEncoding.EncodeToString(kp.PublicKey), base64.StdEncoding.EncodeToString(kp.PrivateKey)))
}

//export GenerateX25519KeyPair
func GenerateX25519KeyPair() *C.char {
	pub, priv, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return C.CString("error: " + err.Error())
	}
	return C.CString(fmt.Sprintf("%s:%s", hex.EncodeToString(pub[:]), hex.EncodeToString(priv[:])))
}

//export DeriveSharedSecretX25519
func DeriveSharedSecretX25519(priv *C.char, pub *C.char) *C.char {
	privHex := C.GoString(priv)
	pubHex := C.GoString(pub)

	privBytes, _ := hex.DecodeString(privHex)
	pubBytes, _ := hex.DecodeString(pubHex)

	if len(privBytes) != 32 || len(pubBytes) != 32 {
		return C.CString("error: keys must be 32 bytes")
	}

	var privArr, pubArr [32]byte
	copy(privArr[:], privBytes)
	copy(pubArr[:], pubBytes)

	shared, err := crypto.DeriveSharedSecretX25519(privArr, pubArr)
	if err != nil {
		return C.CString("error: " + err.Error())
	}
	return C.CString(hex.EncodeToString(shared[:]))
}


//export FreeString
func FreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

func main() {}
