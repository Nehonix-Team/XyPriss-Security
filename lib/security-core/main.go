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
func HashPassword(pass *C.char, algo *C.char) *C.char {
	p := C.GoString(pass)
	a := C.GoString(algo)
	var hash string
	var err error

	switch a {
	case "scrypt":
		hash, err = password.HashScrypt(p)
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
func GeneratePassword(length C.int) *C.char {
	p := password.Generate(int(length), "")
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

// --- STANDALONE CRYPTO (REPLACING EXTERNAL JS CRYPTO) ---

//export GetSHA256
func GetSHA256(data *C.char, length C.int) *C.char {
	b := C.GoBytes(unsafe.Pointer(data), length)
	h := crypto.SHA256(b)
	return C.CString(hex.EncodeToString(h))
}

//export GetHMAC
func GetHMAC(key *C.char, keyLen C.int, data *C.char, dataLen C.int) *C.char {
	k := C.GoBytes(unsafe.Pointer(key), keyLen)
	d := C.GoBytes(unsafe.Pointer(data), dataLen)
	h := crypto.HMAC_SHA256(k, d)
	return C.CString(hex.EncodeToString(h))
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

//export FreeString
func FreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

func main() {}
