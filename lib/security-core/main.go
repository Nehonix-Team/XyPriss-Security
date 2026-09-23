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
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/nehonix/xypriss-security-core/internal/crypto"
	"github.com/nehonix/xypriss-security-core/internal/password"
	"github.com/nehonix/xypriss-security-core/internal/quantum/kyber"
	"github.com/nehonix/xypriss-security-core/internal/quantum/lwe"
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

	// Helper to resolve data (handles stdin via '-')
	resolveData := func(idx int) []byte {
		if idx >= len(args) {
			return nil
		}
		val := args[idx]
		if val == "-" {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				errorExit("failed to read from stdin: " + err.Error())
			}
			return data
		}
		// Default: treat as hex string if it's a 'raw' data command, or plaintext?
		// Most current commands use hex.DecodeString(args[idx])
		d, _ := hex.DecodeString(val)
		return d
	}

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

		hash, err := password.HashPassword(pass, algo, iterations, memory, parallelism)
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
		data := resolveData(0)
		algo := args[1]
		h, err := crypto.HashWithAlgo(data, algo)
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Print(hex.EncodeToString(h))

	case "get-sha256":
		if len(args) < 1 {
			errorExit("missing data for get-sha256")
		}
		data := resolveData(0)
		fmt.Print(hex.EncodeToString(crypto.SHA256(data)))

	case "get-hmac":
		if len(args) < 3 {
			errorExit("missing arguments for get-hmac")
		}
		key, _ := hex.DecodeString(args[0])
		data := resolveData(1)
		algo := args[2]
		h, err := crypto.HMACWithAlgo(key, data, algo)
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Print(hex.EncodeToString(h))

	case "hkdf":
		if len(args) < 4 {
			errorExit("missing arguments for hkdf")
		}
		ikm := resolveData(0)
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
		var pass []byte
		if args[0] == "-" {
			pass, _ = io.ReadAll(os.Stdin)
		} else {
			pass = []byte(args[0])
		}
		salt, _ := hex.DecodeString(args[1])
		iterations, _ := strconv.Atoi(args[2])
		keyLen, _ := strconv.Atoi(args[3])
		algo := args[4]
		h, err := crypto.PBKDF2WithAlgo(pass, salt, iterations, keyLen, algo)
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Print(hex.EncodeToString(h))

	case "scrypt":
		if len(args) < 6 {
			errorExit("missing arguments for scrypt")
		}
		var pass []byte
		if args[0] == "-" {
			pass, _ = io.ReadAll(os.Stdin)
		} else {
			pass = []byte(args[0])
		}
		salt, _ := hex.DecodeString(args[1])
		cost, _ := strconv.Atoi(args[2])
		r, _ := strconv.Atoi(args[3])
		p, _ := strconv.Atoi(args[4])
		keyLen, _ := strconv.Atoi(args[5])
		k, err := crypto.ScryptKey(pass, salt, cost, r, p, keyLen)
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Print(hex.EncodeToString(k))

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
		pkg, err := crypto.EncryptWithAlgo(plaintext, key, nil, algo)
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
		dec, err := crypto.DecryptWithAlgo(data, key, nonce, tag, nil, algo)
		if err != nil {
			errorExit(err.Error())
		}
		fmt.Print(string(dec))

	case "encrypt-raw":
		if len(args) < 3 {
			errorExit("missing arguments for encrypt-raw")
		}
		data := resolveData(0)
		key, _ := hex.DecodeString(args[1])
		algo := args[2]
		pkg, err := crypto.EncryptWithAlgo(data, key, nil, algo)
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
		dec, err := crypto.DecryptWithAlgo(data, key, nonce, tag, nil, algo)
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

	case "ed25519-verify":
		if len(args) < 3 {
			errorExit("missing arguments for ed25519-verify")
		}
		pubKey, _ := hex.DecodeString(args[0])
		data := resolveData(1)
		sig, _ := base64.StdEncoding.DecodeString(args[2])
		if crypto.VerifyEd25519(pubKey, data, sig) {
			fmt.Print("1")
		} else {
			fmt.Print("0")
		}

	default:
		errorExit("unknown command: " + cmd)
	}
}

func errorExit(msg string) {
	fmt.Print("error: " + msg)
	os.Exit(0) // Exit with 0 but prefix with error: so bridge can catch it
}
