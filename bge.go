package zanolib

type BGEProof struct {
	A  Value256   // public_key, premultiplied by 1/8
	B  Value256   // public_key, premultiplied by 1/8
	Pk []Value256 // premultiplied by 1/8, size = m
	F  []Value256 // scalar_vec_t size = m * (n - 1)
	Y  Value256   // scalar_t
	Z  Value256   // scalar_t
}
