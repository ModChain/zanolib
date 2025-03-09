package zanocrypto

import (
	"math"
	"math/bits"
)

func ceilLog2(x int) int {
	// By definition, ceil(log2(1)) = 0
	if x <= 1 {
		return 0
	}
	// bits.Len(uint(x - 1)) gives the number of bits needed
	// to represent (x-1), which is effectively ceil(log2(x)).
	return bits.Len(uint(x - 1))
}

// intPow is a integer version of pow()
func intPow(base, exp int) int {
	result := 1
	for {
		if exp&1 == 1 {
			result *= base
		}
		exp >>= 1
		if exp == 0 {
			break
		}
		base *= base
	}

	return result
}

// ceilLogN returns the smallest integer m such that m^n >= ringSize.
func ceilLogN(ringSize, n int) int {
	if ringSize <= 1 {
		return 1
	}
	if n == 1 {
		return ringSize
	}

	floatGuess := math.Pow(float64(ringSize), 1.0/float64(n))
	m := int(math.Ceil(floatGuess))

	// Correct any floating-point rounding errors:
	for intPow(m, n) < ringSize {
		m++
	}
	for m > 1 && intPow(m-1, n) >= ringSize {
		m--
	}
	return m
}
