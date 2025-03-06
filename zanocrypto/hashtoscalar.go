package zanocrypto

import (
	"filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

// hashToScalar is a helper that does:
//
//	scalar = keccak256( data ) mod l
func HashToScalar(data []byte) *edwards25519.Scalar {
	// Combine ephemeralPoint + realOutInTxIndex in a buffer
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	sum := hash.Sum(nil)

	var wideB [64]byte
	copy(wideB[:], sum)

	return must(new(edwards25519.Scalar).SetUniformBytes(wideB[:]))
}
