package zanocrypto

import "math/bits"

func ceilLog2(x int) int {
	// By definition, ceil(log2(1)) = 0
	if x <= 1 {
		return 0
	}
	// bits.Len(uint(x - 1)) gives the number of bits needed
	// to represent (x-1), which is effectively ceil(log2(x)).
	return bits.Len(uint(x - 1))
}
