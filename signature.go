package zanolib

type ZCSig struct {
	// ZC_sig
	PseudoOutAmountCommitment [32]byte // premultiplied by 1/8
	PseudoOutBlindedAssetId   [32]byte // premultiplied by 1/8
	// crypto::CLSAG_GGX_signature_serialized clsags_ggx
	GGX *CLSAG_Sig
}

type CLSAG_Sig struct {
	C   [32]byte   // scalar_t
	R_G [][32]byte // for G-components (layers 0, 1),    size = size of the ring
	R_X [][32]byte // for X-component  (layer 2),        size = size of the ring
	K1  [32]byte   // public_key auxiliary key image for layer 1 (G)
	K2  [32]byte   // public_key auxiliary key image for layer 2 (X)
}
