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

// HsB performs HashToScalar on a slice of byters
func HsB(vals ...byter) *edwards25519.Scalar {
	h := sha3.NewLegacyKeccak256()
	for _, v := range vals {
		h.Write(v.Bytes())
	}

	var wideB [64]byte
	copy(wideB[:], h.Sum(nil))

	return must(new(edwards25519.Scalar).SetUniformBytes(wideB[:]))
}
