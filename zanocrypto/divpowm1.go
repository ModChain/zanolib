package zanocrypto

import "github.com/ModChain/edwards25519"

// FeDivPowM1 implements the Monero/Ed25519 "fe_divpowm1" logic, which
// computes r = (u^(m+1)) * (v^(-(m+1))) via a large exponent (the so-called
// (q-5)/8 exponent in the field).
func FeDivPowM1(r, u, v *edwards25519.FieldElement) {
	var v3, uv7, t0, t1, t2 edwards25519.FieldElement

	// v3 = v^3
	edwards25519.FeSquare(&v3, v)   // v^2
	edwards25519.FeMul(&v3, &v3, v) // v^3

	// uv7 = u * v^7
	//   (First compute v^7 by v^3 -> v^6 -> v^7, then multiply by u)
	edwards25519.FeSquare(&uv7, &v3)  // v^6
	edwards25519.FeMul(&uv7, &uv7, v) // v^7
	edwards25519.FeMul(&uv7, &uv7, u) // u * v^7

	// Now exponentiate uv7 by (2^255 - 21), effectively. (q-5)/8 in some references.
	// The Monero code inlines "fe_pow22523(uv7, uv7)" as the following:

	// Step 1
	edwards25519.FeSquare(&t0, &uv7)   // t0 = uv7^2
	edwards25519.FeSquare(&t1, &t0)    // t1 = uv7^4
	edwards25519.FeSquare(&t1, &t1)    // t1 = uv7^8
	edwards25519.FeMul(&t1, &uv7, &t1) // t1 = uv7^9
	edwards25519.FeMul(&t0, &t0, &t1)  // t0 = uv7^2 * uv7^9 = uv7^11
	edwards25519.FeSquare(&t0, &t0)    // t0 = uv7^22
	edwards25519.FeMul(&t0, &t1, &t0)  // t0 = uv7^9 * uv7^22 = uv7^31

	// Step 2
	edwards25519.FeSquare(&t1, &t0) // t1 = uv7^62
	for i := 0; i < 4; i++ {
		edwards25519.FeSquare(&t1, &t1) // uv7^(62 * 2^4) = uv7^62 * 2^4 = uv7^(62 + 4??)
	}
	edwards25519.FeMul(&t0, &t1, &t0) // t0 = uv7^(31 + something)...

	// Step 3
	edwards25519.FeSquare(&t1, &t0)
	for i := 0; i < 9; i++ {
		edwards25519.FeSquare(&t1, &t1)
	}
	edwards25519.FeMul(&t1, &t1, &t0)

	// Step 4
	edwards25519.FeSquare(&t2, &t1)
	for i := 0; i < 19; i++ {
		edwards25519.FeSquare(&t2, &t2)
	}
	edwards25519.FeMul(&t1, &t2, &t1)

	// Step 5
	for i := 0; i < 10; i++ {
		edwards25519.FeSquare(&t1, &t1)
	}
	edwards25519.FeMul(&t0, &t1, &t0)

	// Step 6
	edwards25519.FeSquare(&t1, &t0)
	for i := 0; i < 49; i++ {
		edwards25519.FeSquare(&t1, &t1)
	}
	edwards25519.FeMul(&t1, &t1, &t0)

	// Step 7
	edwards25519.FeSquare(&t2, &t1)
	for i := 0; i < 99; i++ {
		edwards25519.FeSquare(&t2, &t2)
	}
	edwards25519.FeMul(&t1, &t2, &t1)

	// Step 8
	for i := 0; i < 50; i++ {
		edwards25519.FeSquare(&t1, &t1)
	}
	edwards25519.FeMul(&t0, &t1, &t0)

	edwards25519.FeSquare(&t0, &t0)
	edwards25519.FeSquare(&t0, &t0)

	// t0 = (uv7)^((q-5)/8)
	edwards25519.FeMul(&t0, &t0, &uv7)

	// Multiply by v^3
	edwards25519.FeMul(&t0, &t0, &v3)

	// Finally, multiply by u => r
	edwards25519.FeMul(r, &t0, u)
}
