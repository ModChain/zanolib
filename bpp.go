package zanolib

type BPPSignature struct {
	Lv    []Value256 // std::vector<public_key> size = ceil( log_2(m * n) )
	Rv    []Value256 // std::vector<public_key>
	A0    Value256   // public_key
	A     Value256   // public_key
	B     Value256   // public_key
	R     Value256   // scalar_t
	S     Value256   // scalar_t
	Delta Value256   // scalar_t
}
