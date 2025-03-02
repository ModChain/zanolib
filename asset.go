package zanolib

import (
	"fmt"
	"io"
)

type ZCAssetSurjectionProof struct {
	// zc_asset_surjection_proof
	BGEProofs []*BGEProof // std::vector<crypto::BGE_proof_s> bge_proofs
}

func (obj *ZCAssetSurjectionProof) ReadFrom(r io.Reader) (int64, error) {
	rc := rc(r)

	ln, err := VarintReadUint64(rc)
	if err != nil {
		return rc.error(err)
	}
	if ln > 128 {
		return rc.error(fmt.Errorf("too many proofs: %d > 128", ln))
	}
	obj.BGEProofs = make([]*BGEProof, ln)
	for n := range obj.BGEProofs {
		sub := new(BGEProof)
		err = rc.into(sub)
		if err != nil {
			return rc.error(err)
		}
		obj.BGEProofs[n] = sub
	}
	return rc.ret()
}
