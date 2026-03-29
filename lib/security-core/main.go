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

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/nehonix/xypriss-security-core/internal/crypto"
	"github.com/nehonix/xypriss-security-core/internal/password"
	"github.com/nehonix/xypriss-security-core/internal/quantum/kyber"
	"github.com/nehonix/xypriss-security-core/internal/quantum/lwe"
	"golang.org/x/crypto/argon2"
)

/**
 * XyPriss Security Core - CLI Bridge Implementation
 * Replacing FFI with direct process spawning for cross-platform stability.
 */

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: xypriss-security-core <command> [args...]")
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "hash-password":
		if len(args) < 5 {
			errorExit("missing arguments for hash-password")
		}
		pass := args[0]
		algo := args[1]
		iterations, _ := strconv.Atoi(args[2])
		memory, _ := strconv.Atoi(args[3])
		parallelism, _ := strconv.Atoi(args[4])

		var hash string
		var err error
		switch algo {
		case "scrypt":
			hash, err = password.HashScrypt(pass)
		case "pbkdf2":
			hash, err = password.HashPBKDF2(pass, iterations)
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
			h := argon2.IDKey([]byte(pass), salt, params.Time, params.Memory, params.Threads, params.KeyLen)

			b64Salt := base64.RawStdEncoding.EncodeToString(salt)
			b64Hash := base64.RawStdEncoding.EncodeToString(h)
			pStr := fmt.Sprintf("v=%d,m=%d,t=%d,p=%d", argon2.Version, params.Memory, params.Time, params.Threads)
			hash = fmt.Sprintf("$xypriss$argon2id$%s$%s$%s", pStr, b64Salt, b64Hash)
		default:
			hash, err = password.HashArgon2id(pass)
		}

		if err != nil {
			errorExit(err.Error())
		}
		fmt.Print(hash)

	case "verify-password":
		if len(args) < 2 {
			errorExit("missing arguments for verify-password")
		}
		if password.Verify(args[0], args[1]) {
			fmt.Print("1")
		} else {
			fmt.Print("0")
		}

	case "is-hashed":
		if len(args) < 1 {
			errorExit("missing hash for is-hashed")
		}
		expectedAlgo := ""
		if len(args) > 1 {
			expectedAlgo = args[1]
		}

		result := false
		if expectedAlgo != "" {
			result = password.IsHashedWithAlgo(args[0], expectedAlgo)
		} else {
			result = password.IsHashed(args[0])
		}

		if result {
			fmt.Print("1")
		} else {
			fmt.Print("0")
		}

	case "generate-password":
		if len(args) < 2 {
			errorExit("missing arguments for generate-password")
		}
		length, _ := strconv.Atoi(args[0])
		fmt.Print(password.Generate(length, args[1]))

	case "get-random-bytes":
		if len(args) < 1 {
			errorExit("missing length for get-random-bytes")
		}
		length, _ := strconv.Atoi(args[0])
		b, err := crypto.RandomBytes(length)
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Print(hex.EncodeToString(b))

	case "get-random-int":
		if len(args) < 1 {
			errorExit("missing max for get-random-int")
		}
		max, _ := strconv.ParseInt(args[0], 10, 64)
		val, err := crypto.RandomInt63(max)
		if err != nil {
			fmt.Print("-1")
		} else {
			fmt.Print(val)
		}

	case "generate-otp":
		if len(args) < 1 {
			errorExit("missing length for generate-otp")
		}
		digits, _ := strconv.Atoi(args[0])
		otp, err := crypto.GenerateOTP(digits)
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Print(otp)

	case "get-hash":
		if len(args) < 2 {
			errorExit("missing arguments for get-hash")
		}
		data, _ := hex.DecodeString(args[0])
		algo := strings.ToLower(args[1])
		var h []byte
		var err error
		switch algo {
		case "sha512":
			h = crypto.SHA512(data)
		case "sha3-256":
			h = crypto.SHA3_256(data)
		case "blake2b":
			h, err = crypto.Blake2b256(data)
		default:
			h = crypto.SHA256(data)
		}
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Print(hex.EncodeToString(h))

	case "get-sha256":
		if len(args) < 1 {
			errorExit("missing data for get-sha256")
		}
		data, _ := hex.DecodeString(args[0])
		fmt.Print(hex.EncodeToString(crypto.SHA256(data)))

	case "get-hmac":
		if len(args) < 3 {
			errorExit("missing arguments for get-hmac")
		}
		key, _ := hex.DecodeString(args[0])
		data, _ := hex.DecodeString(args[1])
		algo := strings.ToLower(args[2])
		var h []byte
		var err error
		switch algo {
		case "sha512":
			h = crypto.HMAC_SHA512(key, data)
		case "blake2b":
			h, err = crypto.Blake2bMAC(key, data)
		default:
			h = crypto.HMAC_SHA256(key, data)
		}
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Print(hex.EncodeToString(h))

	case "hkdf":
		if len(args) < 4 {
			errorExit("missing arguments for hkdf")
		}
		ikm, _ := hex.DecodeString(args[0])
		salt, _ := hex.DecodeString(args[1])
		info, _ := hex.DecodeString(args[2])
		outLen, _ := strconv.Atoi(args[3])
		out, err := crypto.HKDF(ikm, salt, info, outLen)
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Print(hex.EncodeToString(out))

	case "pbkdf2":
		if len(args) < 5 {
			errorExit("missing arguments for pbkdf2")
		}
		pass := []byte(args[0])
		salt, _ := hex.DecodeString(args[1])
		iterations, _ := strconv.Atoi(args[2])
		keyLen, _ := strconv.Atoi(args[3])
		algo := strings.ToLower(args[4])
		var h []byte
		if algo == "sha512" {
			h = crypto.PBKDF2SHA512(pass, salt, iterations, keyLen)
		} else {
			h = crypto.PBKDF2SHA256(pass, salt, iterations, keyLen)
		}
		fmt.Print(hex.EncodeToString(h))

	case "constant-time-compare":
		if len(args) < 2 {
			errorExit("missing arguments for constant-time-compare")
		}
		a, _ := hex.DecodeString(args[0])
		b, _ := hex.DecodeString(args[1])
		if crypto.ConstantTimeEqual(a, b) {
			fmt.Print("1")
		} else {
			fmt.Print("0")
		}

	case "encrypt":
		if len(args) < 3 {
			errorExit("missing arguments for encrypt")
		}
		plaintext := []byte(args[0])
		key, _ := hex.DecodeString(args[1])
		algo := args[2]
		var pkg *crypto.EncryptedPackage
		var err error
		if algo == "chacha20" {
			pkg, err = crypto.EncryptChaCha20Poly1305(plaintext, key, nil)
		} else {
			pkg, err = crypto.EncryptAESGCM(plaintext, key, nil)
		}
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Printf("%s:%s:%s", hex.EncodeToString(pkg.Nonce), hex.EncodeToString(pkg.AuthTag), hex.EncodeToString(pkg.Data))

	case "decrypt":
		if len(args) < 3 {
			errorExit("missing arguments for decrypt")
		}
		parts := strings.Split(args[0], ":")
		if len(parts) != 3 {
			errorExit("invalid encrypted format")
		}
		key, _ := hex.DecodeString(args[1])
		algo := args[2]
		nonce, _ := hex.DecodeString(parts[0])
		tag, _ := hex.DecodeString(parts[1])
		data, _ := hex.DecodeString(parts[2])
		var dec []byte
		var err error
		if algo == "chacha20" {
			dec, err = crypto.DecryptChaCha20Poly1305(data, key, nonce, tag, nil)
		} else {
			dec, err = crypto.DecryptAESGCM(data, key, nonce, tag, nil)
		}
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Print(string(dec))

	case "encrypt-raw":
		if len(args) < 3 {
			errorExit("missing arguments for encrypt-raw")
		}
		data, _ := hex.DecodeString(args[0])
		key, _ := hex.DecodeString(args[1])
		algo := args[2]
		var pkg *crypto.EncryptedPackage
		var err error
		if algo == "chacha20" {
			pkg, err = crypto.EncryptChaCha20Poly1305(data, key, nil)
		} else {
			pkg, err = crypto.EncryptAESGCM(data, key, nil)
		}
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Printf("%s:%s:%s", hex.EncodeToString(pkg.Nonce), hex.EncodeToString(pkg.AuthTag), hex.EncodeToString(pkg.Data))

	case "decrypt-raw":
		if len(args) < 3 {
			errorExit("missing arguments for decrypt-raw")
		}
		parts := strings.Split(args[0], ":")
		if len(parts) != 3 {
			errorExit("invalid encrypted format")
		}
		key, _ := hex.DecodeString(args[1])
		algo := args[2]
		nonce, _ := hex.DecodeString(parts[0])
		tag, _ := hex.DecodeString(parts[1])
		data, _ := hex.DecodeString(parts[2])
		var dec []byte
		var err error
		if algo == "chacha20" {
			dec, err = crypto.DecryptChaCha20Poly1305(data, key, nonce, tag, nil)
		} else {
			dec, err = crypto.DecryptAESGCM(data, key, nonce, tag, nil)
		}
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Print(hex.EncodeToString(dec))

	case "kyber-generate-key-pair":
		kp, err := kyber.GenerateKeyPair()
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Printf("%s:%s", base64.StdEncoding.EncodeToString(kp.PublicKey), base64.StdEncoding.EncodeToString(kp.PrivateKey))

	case "generate-x25519-key-pair":
		pub, priv, err := crypto.GenerateX25519KeyPair()
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Printf("%s:%s", hex.EncodeToString(pub[:]), hex.EncodeToString(priv[:]))

	case "derive-shared-secret-x25519":
		if len(args) < 2 {
			errorExit("missing arguments for derive-shared-secret-x25519")
		}
		privBytes, _ := hex.DecodeString(args[0])
		pubBytes, _ := hex.DecodeString(args[1])
		if len(privBytes) != 32 || len(pubBytes) != 32 {
			errorExit("keys must be 32 bytes")
		}
		var privArr, pubArr [32]byte
		copy(privArr[:], privBytes)
		copy(pubArr[:], pubBytes)
		shared, err := crypto.DeriveSharedSecretX25519(privArr, pubArr)
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Print(hex.EncodeToString(shared[:]))

	case "sample-lwe-error":
		val, _ := lwe.SampleCBD(2)
		fmt.Print(val)

	case "get-byte-length":
		if len(args) < 1 {
			errorExit("missing string for get-byte-length")
		}
		fmt.Print(len([]byte(args[0])))
	case "is-valid-byte-length":
		if len(args) < 2 {
			errorExit("missing arguments for is-valid-byte-length")
		}
		expectedLen, _ := strconv.Atoi(args[1])
		if len([]byte(args[0])) == expectedLen {
			fmt.Print("1")
		} else {
			fmt.Print("0")
		}

	case "generate-rsa-key-json":
		kp, err := crypto.GenerateRSAKeyJSON()
		if err != nil {
			errorExit(err.Error())
		}
		out, _ := json.Marshal(kp)
		fmt.Print(string(out))

	case "rsa-sign":
		if len(args) < 2 {
			errorExit("missing arguments for rsa-sign")
		}
		priv, err := crypto.ParseRSAPrivateKey([]byte(args[0]))
		if err != nil {
			errorExit(err.Error())
		}
		sig, err := crypto.RSASign(priv, []byte(args[1]))
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Print(hex.EncodeToString(sig))

	case "rsa-verify":
		if len(args) < 3 {
			errorExit("missing arguments for rsa-verify")
		}
		pub, err := crypto.ParseRSAPublicKey([]byte(args[0]))
		if err != nil {
			errorExit(err.Error())
		}
		sig, _ := hex.DecodeString(args[2])
		err = crypto.RSAVerify(pub, []byte(args[1]), sig)
		if err != nil {
			fmt.Print("0")
		} else {
			fmt.Print("1")
		}

	case "rsa-encrypt":
		if len(args) < 2 {
			errorExit("missing arguments for rsa-encrypt")
		}
		pub, err := crypto.ParseRSAPublicKey([]byte(args[0]))
		if err != nil {
			errorExit(err.Error())
		}
		enc, err := crypto.RSAEncrypt(pub, []byte(args[1]))
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Print(hex.EncodeToString(enc))

	case "rsa-decrypt":
		if len(args) < 2 {
			errorExit("missing arguments for rsa-decrypt")
		}
		priv, err := crypto.ParseRSAPrivateKey([]byte(args[0]))
		if err != nil {
			errorExit(err.Error())
		}
		data, _ := hex.DecodeString(args[1])
		dec, err := crypto.RSADecrypt(priv, data)
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Print(string(dec))

	case "encrypt-file":
		if len(args) < 4 {
			errorExit("missing arguments for encrypt-file")
		}
		inPath := args[0]
		outPath := args[1]
		key, _ := hex.DecodeString(args[2])
		algo := args[3]
		err := crypto.EncryptFile(inPath, outPath, key, algo)
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Print("OK")

	case "decrypt-file":
		if len(args) < 3 {
			errorExit("missing arguments for decrypt-file")
		}
		inPath := args[0]
		outPath := args[1]
		key, _ := hex.DecodeString(args[2])
		err := crypto.DecryptFile(inPath, outPath, key)
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Print("OK")

	default:
		errorExit("unknown command: " + cmd)
	}
}

func errorExit(msg string) {
	fmt.Print("error: " + msg)
	os.Exit(0) // Exit with 0 but prefix with error: so bridge can catch it
}
