package zanocrypto

import (
	"github.com/ModChain/edwards25519"
	"golang.org/x/crypto/sha3"
)

// hashToScalar is a helper that does:
//
//	scalar = keccak256( data ) mod l
func HashToScalar(data []byte) [32]byte {
	var out [32]byte

	// Combine ephemeralPoint + realOutInTxIndex in a buffer
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	sum := hash.Sum(nil)

	copy(out[:], sum)

	// reduce mod l
	edwards25519.ScReduce32(&out, &out) // out = sum mod l

	return out
}
