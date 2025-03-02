package zanolib

type ZCOutsRangeProof struct {
	// zc_outs_range_proof
	BPP *BPPSignature // for commitments in form: amount * U + mask * G
	// crypto::vector_UG_aggregation_proof_serialized
	AggregationProof *UGAggProof // E'_j = e_j * U + y'_j * G    +   vector Shnorr
}

type UGAggProof struct {
	AmountCommitmentsForRPAgg [][32]byte // std::vector<public_key> E' = e * U + y' * G, premultiplied by 1/8
	Y0s                       [][32]byte // scalar_vec_t
	Y1s                       [][32]byte // scalar_vec_t
	C                         [32]byte   // common challenge
}

// First part of a double Schnorr proof:
//  1. for txs without ZC inputs: proves that balance point = lin(G) (cancels out G component of outputs' amount commitments, asset tags assumed to be H (native coin) and non-blinded)
//  2. for txs with    ZC inputs: proves that balance point = lin(X) (cancels out X component of blinded asset tags within amount commitments for both outputs and inputs (pseudo outs))
//
// Second part:
//
//	proof of knowing transaction secret key (with respect to G)
type ZCBalanceProof struct {
	// zc_balance_proof
	DSS *GenericDoubleSchnorrSig // crypto::generic_double_schnorr_sig_s
}

type GenericDoubleSchnorrSig struct {
	C  [32]byte
	Y0 [32]byte
	Y1 [32]byte
}
