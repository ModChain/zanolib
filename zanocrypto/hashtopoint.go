package zanocrypto

import "github.com/ModChain/edwards25519"

// HashToPoint is the Go equivalent of the C++ hash_to_point function.
// It takes a 32-byte hash 'h', interprets it as a field element, constructs
// a projective point from it, and then serializes that point back to a 32-byte array.
func HashToPoint(h *[32]byte) (res [32]byte) {
	// 1. Create a projective group element to hold the intermediate representation.
	var point edwards25519.ProjectiveGroupElement

	// 2. Convert the 32-byte hash into a projective group element.
	//    This mimics ge_fromfe_frombytes_vartime in the C++ code.
	geFromFeFromBytesVartime(&point, h)

	// 3. Convert (serialize) the projective group element back into a 32-byte array.
	//    This mimics ge_tobytes in the C++ code.
	point.ToBytes(&res)

	return res
}
