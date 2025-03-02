package zanolib

type BGEProof struct {
	A  [32]byte   // public_key, premultiplied by 1/8
	B  [32]byte   // public_key, premultiplied by 1/8
	Pk [][32]byte // premultiplied by 1/8, size = m
	F  [][32]byte // scalar_vec_t size = m * (n - 1)
	Y  [32]byte   // scalar_t
	Z  [32]byte   // scalar_t
}
