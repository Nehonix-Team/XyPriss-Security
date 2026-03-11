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

package kyber

import (
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// KeyPair represents a real Kyber-768 keypair
type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

// GenerateKeyPair produces a real Kyber-768 keypair using Cloudflare Circl
func GenerateKeyPair() (*KeyPair, error) {
	scheme := kyber768.Scheme()
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	pkBytes, _ := pk.MarshalBinary()
	skBytes, _ := sk.MarshalBinary()

	return &KeyPair{
		PublicKey:  pkBytes,
		PrivateKey: skBytes,
	}, nil
}

// Encapsulate generates a shared secret and ciphertext for a given public key
func Encapsulate(publicKeyBytes []byte) (sharedSecret []byte, ciphertext []byte, err error) {
	scheme := kyber768.Scheme()
	pk, err := scheme.UnmarshalBinaryPublicKey(publicKeyBytes)
	if err != nil {
		return nil, nil, err
	}

	ct, ss, err := scheme.Encapsulate(pk)
	return ss, ct, err
}

// Decapsulate recovers the shared secret from the ciphertext using the private key
func Decapsulate(ciphertextBytes, privateKeyBytes []byte) (sharedSecret []byte, err error) {
	scheme := kyber768.Scheme()
	sk, err := scheme.UnmarshalBinaryPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	return scheme.Decapsulate(sk, ciphertextBytes)
}
