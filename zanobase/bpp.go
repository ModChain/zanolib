package zanobase

type BPPSignature struct {
	Lv    []*Point // std::vector<public_key> size = ceil( log_2(m * n) )
	Rv    []*Point // std::vector<public_key>
	A0    *Point   // public_key
	A     *Point   // public_key
	B     *Point   // public_key
	R     *Scalar  // scalar_t
	S     *Scalar  // scalar_t
	Delta *Scalar  // scalar_t
}
