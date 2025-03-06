package zanobase

type ZCSig struct {
	// ZC_sig
	PseudoOutAmountCommitment Value256 // premultiplied by 1/8
	PseudoOutBlindedAssetId   Value256 // premultiplied by 1/8
	// crypto::CLSAG_GGX_signature_serialized clsags_ggx
	GGX *CLSAG_Sig
}

type CLSAG_Sig struct {
	C  *Scalar   // scalar_t
	Rg []*Scalar // for G-components (layers 0, 1),    size = size of the ring
	Rx []*Scalar // for X-component  (layer 2),        size = size of the ring
	K1 *Point    // public_key auxiliary key image for layer 1 (G)
	K2 *Point    // public_key auxiliary key image for layer 2 (X)
}

type CLSAG_GGX_Input struct {
	BlindedAssetId   Value256
	StealthAddress   Value256
	AmountCommitment Value256
}
