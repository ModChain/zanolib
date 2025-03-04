package zanocrypto

import (
	"github.com/ModChain/edwards25519"
	"golang.org/x/crypto/sha3"
)

func HashToEC(pubBytes *[32]byte) (*edwards25519.ExtendedGroupElement, error) {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(pubBytes[:])
	hashed := hash.Sum(nil)
	var h [32]byte
	copy(h[:], hashed)

	// 2) Map those 32 bytes to a curve point: ge_fromfe_frombytes_vartime
	var point edwards25519.ProjectiveGroupElement
	geFromFeFromBytesVartime(&point, &h)

	// 3) Multiply by 8 => three doublings
	var tmp edwards25519.CompletedGroupElement
	point.Double(&tmp) // 2×
	tmp.ToProjective(&point)
	point.Double(&tmp) // 4×
	tmp.ToProjective(&point)
	point.Double(&tmp) // 8×

	// 4) Convert to ExtendedGroupElement (ge_p3)
	var out edwards25519.ExtendedGroupElement
	tmp.ToExtended(&out)
	return &out, nil
}

func geFromFeFromBytesVartime(r *edwards25519.ProjectiveGroupElement, s *[32]byte) {
	h0 := load4(s[0:4])
	h1 := load3(s[4:7]) << 6
	h2 := load3(s[7:10]) << 5
	h3 := load3(s[10:13]) << 3
	h4 := load3(s[13:16]) << 2
	h5 := load4(s[16:20])
	h6 := load3(s[20:23]) << 7
	h7 := load3(s[23:26]) << 5
	h8 := load3(s[26:29]) << 4
	h9 := load3(s[29:32]) << 2

	var carry0, carry1, carry2, carry3, carry4 int64
	var carry5, carry6, carry7, carry8, carry9 int64

	// Do the carry chain
	carry9 = (h9 + (1 << 24)) >> 25
	h0 += carry9 * 19
	h9 -= carry9 << 25

	carry1 = (h1 + (1 << 24)) >> 25
	h2 += carry1
	h1 -= carry1 << 25

	carry3 = (h3 + (1 << 24)) >> 25
	h4 += carry3
	h3 -= carry3 << 25

	carry5 = (h5 + (1 << 24)) >> 25
	h6 += carry5
	h5 -= carry5 << 25

	carry7 = (h7 + (1 << 24)) >> 25
	h8 += carry7
	h7 -= carry7 << 25

	carry0 = (h0 + (1 << 25)) >> 26
	h1 += carry0
	h0 -= carry0 << 26

	carry2 = (h2 + (1 << 25)) >> 26
	h3 += carry2
	h2 -= carry2 << 26

	carry4 = (h4 + (1 << 25)) >> 26
	h5 += carry4
	h4 -= carry4 << 26

	carry6 = (h6 + (1 << 25)) >> 26
	h7 += carry6
	h6 -= carry6 << 26

	carry8 = (h8 + (1 << 25)) >> 26
	h9 += carry8
	h8 -= carry8 << 26

	var u edwards25519.FieldElement
	u[0] = h0
	u[1] = h1
	u[2] = h2
	u[3] = h3
	u[4] = h4
	u[5] = h5
	u[6] = h6
	u[7] = h7
	u[8] = h8
	u[9] = h9

	// End fe_frombytes.c
	var v, w, x, y, z edwards25519.FieldElement
	var sign byte

	// v = 2 * u^2
	edwards25519.FeSquare2(&v, &u)

	// w = 1
	edwards25519.FeOne(&w)

	// w = 2*u^2 + 1
	edwards25519.FeAdd(&w, &v, &w)

	// x = w^2
	edwards25519.FeSquare(&x, &w)

	// y = fe_ma2 * v = (-A^2)*v  (Monero code comment says "y = -2 * A^2 * u^2"?)
	edwards25519.FeMul(&y, &FeMa2, &v)

	// x = w^2 + y = w^2 - 2*A^2*u^2
	edwards25519.FeAdd(&x, &x, &y)

	// r->X = (w / x)^(m+1)
	edwards25519.FeDivPowM1(&r.X, &w, &x)

	// y = (r->X)^2
	edwards25519.FeSquare(&y, &r.X)

	// x = y * x
	edwards25519.FeMul(&x, &y, &x)

	// y = w - x
	edwards25519.FeSub(&y, &w, &x)

	// z = fe_ma = -A
	edwards25519.FeCopy(&z, &FeMa)

	// if (fe_isnonzero(y)) => the "if" that goes to "negative" in C code
	if edwards25519.FeIsNonZero(&y) != 0 {
		// y = w + x
		edwards25519.FeAdd(&y, &w, &x)
		if edwards25519.FeIsNonZero(&y) != 0 {
			// goto negative
			goto NEGATIVE
		} else {
			// fe_mul(r->X, r->X, fe_fffb1)
			edwards25519.FeMul(&r.X, &r.X, &FeFffb1)
		}
	} else {
		// else => fe_mul(r->X, r->X, fe_fffb2)
		edwards25519.FeMul(&r.X, &r.X, &FeFffb2)
	}

	// r->X = r->X * u
	edwards25519.FeMul(&r.X, &r.X, &u)

	// z = z * v = -A * (2*u^2)
	edwards25519.FeMul(&z, &z, &v)

	sign = 0
	goto SETSIGN

NEGATIVE:
	// x = x * fe_sqrtm1
	edwards25519.FeMul(&x, &x, &edwards25519.SqrtM1)
	// y = w - x
	edwards25519.FeSub(&y, &w, &x)
	if edwards25519.FeIsNonZero(&y) != 0 {
		// The C code has an assert that the next line is nonzero check
		// fe_add(y, w, x); !fe_isnonzero(y)
		edwards25519.FeAdd(&y, &w, &x)
		// if still nonzero => something's wrong
		if edwards25519.FeIsNonZero(&y) != 0 {
			panic("assertion failed in ge_fromfe_frombytes_vartime")
		}
		// fe_mul(r->X, r->X, fe_fffb3)
		edwards25519.FeMul(&r.X, &r.X, &FeFffb3)
	} else {
		edwards25519.FeMul(&r.X, &r.X, &FeFffb4)
	}
	// sign = 1
	sign = 1

SETSIGN:
	// if (fe_isnegative(r->X) != sign) => fe_neg(r->X, r->X)
	if edwards25519.FeIsNegative(&r.X) != sign {
		// ensure r->X != 0
		if edwards25519.FeIsNonZero(&r.X) == 0 {
			panic("Unexpected zero field element in setsign")
		}
		edwards25519.FeNeg(&r.X, &r.X)
	}
	// r->Z = z + w
	edwards25519.FeAdd(&r.Z, &z, &w)
	// r->Y = z - w
	edwards25519.FeSub(&r.Y, &z, &w)
	// r->X = r->X * r->Z
	edwards25519.FeMul(&r.X, &r.X, &r.Z)
}
