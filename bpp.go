package zanolib

type BPPSignature struct {
	Lv    [][32]byte // std::vector<public_key> size = ceil( log_2(m * n) )
	Rv    [][32]byte // std::vector<public_key>
	A0    [32]byte   // public_key
	A     [32]byte   // public_key
	B     [32]byte   // public_key
	R     [32]byte   // scalar_t
	S     [32]byte   // scalar_t
	Delta [32]byte   // scalar_t
}
