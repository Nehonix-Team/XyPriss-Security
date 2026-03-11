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
	"math/big"
)

const CharsetFull = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
const CharsetAlphanum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// Generate random password with given length and charset.
func Generate(length int, charset string) string {
	if charset == "" {
		charset = CharsetFull
	}
	res := make([]byte, length)
	for i := range res {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		res[i] = charset[num.Int64()]
	}
	return string(res)
}
