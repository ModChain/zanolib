package zanolib

import (
	"io"
)

type ZCOutsRangeProof struct {
	// zc_outs_range_proof
	BPP *BPPSignature // for commitments in form: amount * U + mask * G
	// crypto::vector_UG_aggregation_proof_serialized
	AggregationProof *UGAggProof // E'_j = e_j * U + y'_j * G    +   vector Shnorr
}

func (obj *ZCOutsRangeProof) ReadFrom(r io.Reader) (int64, error) {
	rc := rc(r)
	obj.BPP = &BPPSignature{}
	err := rc.into(obj.BPP)
	if err != nil {
		return rc.error(err)
	}
	obj.AggregationProof = new(UGAggProof)
	err = rc.into(obj.AggregationProof)
	if err != nil {
		return rc.error(err)
	}
	return rc.ret()
}

type UGAggProof struct {
	AmountCommitmentsForRPAgg [][32]byte // std::vector<public_key> E' = e * U + y' * G, premultiplied by 1/8
	Y0s                       [][32]byte // scalar_vec_t
	Y1s                       [][32]byte // scalar_vec_t
	C                         [32]byte   // common challenge
}

func (obj *UGAggProof) ReadFrom(r io.Reader) (int64, error) {
	return rc(r).magic(&obj.AmountCommitmentsForRPAgg, &obj.Y0s, &obj.Y1s, &obj.C)
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

func (obj *ZCBalanceProof) ReadFrom(r io.Reader) (int64, error) {
	obj.DSS = new(GenericDoubleSchnorrSig)
	return rc(r).magic(obj.DSS)
}

type GenericDoubleSchnorrSig struct {
	C  [32]byte
	Y0 [32]byte
	Y1 [32]byte
}

func (obj *GenericDoubleSchnorrSig) ReadFrom(r io.Reader) (int64, error) {
	return rc(r).magic(&obj.C, &obj.Y0, &obj.Y1)
}
