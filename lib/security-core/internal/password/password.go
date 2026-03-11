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

package password

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// XyPrissSignature is the mandatory prefix for all XyPrissSecurity hashes.
const XyPrissSignature = "$xypriss$"

// Argon2Config holds Argon2id parameters
type Argon2Config struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}

var DefaultArgon2 = Argon2Config{
	Time:    3,         // Increased from 2 to 3 for robustness
	Memory:  64 * 1024, // 64MB
	Threads: 4,
	KeyLen:  32,
}

// Internal utility to wrap hashes with the XyPriss signature
func wrapWithXyPriss(algo, params, salt, hash string) string {
	// Standard format: $xypriss$<algo>$<params>$<salt>$<hash>
	return fmt.Sprintf("%s%s$%s$%s$%s", XyPrissSignature, algo, params, salt, hash)
}

// HashArgon2id calculates a signed Argon2id hash.
func HashArgon2id(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, DefaultArgon2.Time, DefaultArgon2.Memory, DefaultArgon2.Threads, DefaultArgon2.KeyLen)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	params := fmt.Sprintf("v=%d,m=%d,t=%d,p=%d", argon2.Version, DefaultArgon2.Memory, DefaultArgon2.Time, DefaultArgon2.Threads)

	return wrapWithXyPriss("argon2id", params, b64Salt, b64Hash), nil
}

// HashScrypt calculates a signed Scrypt hash.
func HashScrypt(password string) (string, error) {
	salt := make([]byte, 16)
	rand.Read(salt)

	// Production: N=32768, r=8, p=1
	k, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(k)
	return wrapWithXyPriss("scrypt", "n=32768,r=8,p=1", b64Salt, b64Hash), nil
}

// Verify checks a password against a signed XyPriss hash.
func Verify(password, encodedHash string) bool {
	if !strings.HasPrefix(encodedHash, XyPrissSignature) {
		return false // Mandatory signature check
	}

	// Remove signature for processing
	raw := encodedHash[len(XyPrissSignature):]
	parts := strings.Split(raw, "$")
	if len(parts) < 4 {
		return false
	}

	algo := parts[0]
	params := parts[1]
	saltB64 := parts[2]
	hashB64 := parts[3]

	salt, _ := base64.RawStdEncoding.DecodeString(saltB64)
	decodedHash, _ := base64.RawStdEncoding.DecodeString(hashB64)

	var comparisonHash []byte
	switch algo {
	case "argon2id":
		var m, t uint32
		var p uint8
		// Robust parsing for "v=19,m=65536,t=3,p=4"
		pParts := strings.Split(params, ",")
		for _, pp := range pParts {
			if strings.HasPrefix(pp, "m=") {
				fmt.Sscanf(pp, "m=%d", &m)
			} else if strings.HasPrefix(pp, "t=") {
				fmt.Sscanf(pp, "t=%d", &t)
			} else if strings.HasPrefix(pp, "p=") {
				fmt.Sscanf(pp, "p=%d", &p)
			}
		}
		if t < 1 { t = 1 }
		if p < 1 { p = 1 }
		if m < 8 { m = 8 }
		comparisonHash = argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(decodedHash)))
	case "scrypt":
		comparisonHash, _ = scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	case "pbkdf2":
		comparisonHash = pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
	}

	return constantTimeCompare(decodedHash, comparisonHash)
}

func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
