package zanocrypto

import (
	"filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

// HashToPoint is the Go equivalent of the C++ hash_to_point function.
func HashToPoint(h []byte) *edwards25519.Point {
	point, err := geFromFeFromBytesVartime(h)
	if err != nil {
		panic(err)
	}

	return point
}

// Hp does some extra stuff, and performs the hashing too
//
// src/crypto/crypto-ops.c:4186
// where Hp = 8 * ge_fromfe_frombytes_vartime(cn_fast_hash(data))
func Hp(in []byte) *edwards25519.Point {
	h := sha3.NewLegacyKeccak256()
	h.Write(in)
	p := HashToPoint(h.Sum(nil))
	return p.ScalarMult(ScalarInt(8), p)
}
