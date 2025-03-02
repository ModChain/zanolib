package zanolib

type ZCSig struct {
	// ZC_sig
	PseudoOutAmountCommitment Value256 // premultiplied by 1/8
	PseudoOutBlindedAssetId   Value256 // premultiplied by 1/8
	// crypto::CLSAG_GGX_signature_serialized clsags_ggx
	GGX *CLSAG_Sig
}

type CLSAG_Sig struct {
	C   Value256   // scalar_t
	R_G []Value256 // for G-components (layers 0, 1),    size = size of the ring
	R_X []Value256 // for X-component  (layer 2),        size = size of the ring
	K1  Value256   // public_key auxiliary key image for layer 1 (G)
	K2  Value256   // public_key auxiliary key image for layer 2 (X)
}
