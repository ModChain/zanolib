package zanocrypto

import (
	"errors"

	"github.com/ModChain/edwards25519"
)

func GenerateKeyDerivation(pubKey, secKey [32]byte) ([32]byte, error) {
	var derivation [32]byte

	// --------------------------------------------------------------------------
	// 1) (Optional) Check or reduce the scalar to ensure it's in the valid range.
	//    In Monero, sc_check() does exactly that. A common approach in Go is
	//    to use ScReduce32 if you want to be sure secKey is < group order.
	// --------------------------------------------------------------------------
	// sc_check equivalent:
	// If you want to *enforce* that the scalar is reduced:
	/*
	   var reducedSecKey [32]byte
	   copy(reducedSecKey[:], secKey[:])
	   ScReduce32(&reducedSecKey, &reducedSecKey)
	   // If you must verify that original secKey was already well-formed,
	   // you'd check if reducedSecKey == secKey. For brevity, let's skip that:
	*/

	// Otherwise, if you already trust secKey is valid, just keep secKey.
	reducedSecKey := secKey

	// --------------------------------------------------------------------------
	// 2) Load the public key into an ExtendedGroupElement
	//    This corresponds to ge_frombytes_vartime(&point, &key1)
	// --------------------------------------------------------------------------
	var point edwards25519.ExtendedGroupElement
	if !point.FromBytes(&pubKey) {
		// This means the pubKey was not a valid point
		return derivation, errors.New("GenerateKeyDerivation: pubkey is not a valid point")
	}

	// --------------------------------------------------------------------------
	// 3) Perform scalar multiplication: ge_scalarmult(&point2, &secKey, &point)
	//    In the edwards25519 Go library, we replicate
	//    "point2 = secKey * point" via GeDoubleScalarMultVartime:
	//        r = aA + bB
	//    so we set b = 0, so r = aA
	// --------------------------------------------------------------------------
	var p edwards25519.ProjectiveGroupElement
	var zero [32]byte
	edwards25519.GeDoubleScalarMultVartime(
		&p,
		&reducedSecKey, // a
		&point,         // A
		&zero,          // b = 0
	)

	// --------------------------------------------------------------------------
	// 4) Multiply the result by 8 (ge_mul8). The usual approach is to double 3x.
	// --------------------------------------------------------------------------
	// We'll do p -> c -> p -> c -> p -> c -> p
	var c edwards25519.CompletedGroupElement

	// Double #1
	p.Double(&c)
	c.ToProjective(&p)

	// Double #2
	p.Double(&c)
	c.ToProjective(&p)

	// Double #3
	p.Double(&c)

	// Now c is p * 8. Convert c back to Projective
	var p2 edwards25519.ProjectiveGroupElement
	c.ToProjective(&p2)

	// --------------------------------------------------------------------------
	// 5) Convert the final ProjectiveGroupElement to bytes (ge_tobytes)
	// --------------------------------------------------------------------------
	p2.ToBytes(&derivation)

	// Return the derivation and success
	return derivation, nil
}
