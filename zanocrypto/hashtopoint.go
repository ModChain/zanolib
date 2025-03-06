package zanocrypto

import "filippo.io/edwards25519"

// HashToPoint is the Go equivalent of the C++ hash_to_point function.
func HashToPoint(h *[32]byte) *edwards25519.Point {
	point, err := geFromFeFromBytesVartime(h)
	if err != nil {
		panic(err)
	}

	return point
}
