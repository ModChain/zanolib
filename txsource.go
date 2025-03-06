package zanolib

import (
	"filippo.io/edwards25519"
	"github.com/ModChain/zanolib/zanobase"
	"github.com/ModChain/zanolib/zanocrypto"
)

type TxSourceOutputEntry struct {
	OutReference     *zanobase.Variant // TxOutRef // either global output index or ref_by_id
	StealthAddress   *zanobase.Point   // crypto::public_key, a.k.a output's one-time public key
	ConcealingPoint  *zanobase.Point   // only for ZC outputs
	AmountCommitment *zanobase.Point   // only for ZC outputs
	BlindedAssetID   *zanobase.Point   // only for ZC outputs
}

type TxSource struct {
	Outputs                    []*TxSourceOutputEntry
	RealOutput                 uint64
	RealOutTxKey               *zanobase.Point  // crypto::public_key
	RealOutAmountBlindingMask  *zanobase.Scalar // crypto::scalar_t
	RealOutAssetIdBlindingMask *zanobase.Scalar // crypto::scalar_t
	RealOutInTxIndex           uint64           // size_t, index in transaction outputs vector
	Amount                     uint64
	TransferIndex              uint64
	MultisigId                 zanobase.Value256 // crypto::hash if txin_multisig: multisig output id
	MsSigsCount                uint64            // size_t
	MsKeysCount                uint64            // size_t
	SeparatelySignedTxComplete bool
	HtlcOrigin                 string // for htlc, specify origin. len = 1, content = "\x00" ?
}

func (src *TxSource) IsZC() bool {
	//return !real_out_amount_blinding_mask.is_zero()
	return src.RealOutAssetIdBlindingMask.Scalar.Equal(zanocrypto.ScZero) == 0
}

func (src *TxSource) generateZCSig(sig *zanobase.ZCSig, txHashForSig []byte, ogc *zanobase.GenContext) error {
	//crypto::point_t asset_id_pt(se.asset_id);
	assetId := ogc.AssetIds[0].Point // TODO get asset id for source? How?
	//crypto::point_t source_blinded_asset_id = asset_id_pt + se.real_out_asset_id_blinding_mask * crypto::c_point_X; // T_i = H_i + r_i * X
	sourceBlindedAssetId := new(edwards25519.Point).Add(assetId, new(edwards25519.Point).ScalarMult(src.RealOutAssetIdBlindingMask.Scalar, zanocrypto.C_point_X))
	//ogc.real_zc_ins_asset_ids.emplace_back(asset_id_pt);
	// TODO
	//crypto::scalar_t pseudo_out_amount_blinding_mask = 0;
	var pseudoOutAmountBlindingMask *edwards25519.Scalar
	//crypto::scalar_t pseudo_out_asset_id_blinding_mask = crypto::scalar_t::random();
	// XXX pseudoOutAssetIdBlindingMask := zanocrypto.RandomScalar(rand.Reader)
	// either normal tx or the last signature of consolidated tx -- in both cases we need to calculate non-random blinding mask for pseudo output commitment
	//pseudo_out_amount_blinding_mask = ogc.amount_blinding_masks_sum - ogc.pseudo_out_amount_blinding_masks_sum + (ogc.ao_commitment_in_outputs ? ogc.ao_amount_blinding_mask : -ogc.ao_amount_blinding_mask);      // A_1 - A^p_0 = (f_1 - f'_1) * G   =>  f'_{i-1} = sum{y_j} - sum{f'_i}
	aoAmountBlindingMask := new(edwards25519.Scalar).Set(ogc.AoAmountBlindingMask.Scalar)
	if !ogc.AoCommitmentInOutputs {
		aoAmountBlindingMask = aoAmountBlindingMask.Negate(aoAmountBlindingMask)
	}
	//pseudoOutAmountBlindingMask = new(edwards25519.Scalar).Add(new(edwards25519.Scalar).Subtract(ogc.AmountBlindingMasksSum.Scalar, ogc.PseudoOutAmountBlindingMasksSum.Scalar), aoAmountBlindingMask)
	// ogc.PseudoOutAmountBlindingMasksSum.Scalar seems to be always zero?
	pseudoOutAmountBlindingMask = new(edwards25519.Scalar).Add(ogc.AmountBlindingMasksSum.Scalar, aoAmountBlindingMask)

	//crypto::point_t pseudo_out_blinded_asset_id = source_blinded_asset_id + pseudo_out_asset_id_blinding_mask * crypto::c_point_X;            // T^p_i = T_i + r'_i * X
	pseudoOutBlindedAssetId := new(edwards25519.Point).Add(sourceBlindedAssetId, new(edwards25519.Point).ScalarMult(pseudoOutAmountBlindingMask, zanocrypto.C_point_X))
	//sig.pseudo_out_blinded_asset_id = (crypto::c_scalar_1div8 * pseudo_out_blinded_asset_id).to_public_key();
	sig.PseudoOutBlindedAssetId = &zanobase.Point{new(edwards25519.Point).ScalarMult(zanocrypto.Sc1div8, pseudoOutBlindedAssetId)}

	//ogc.real_in_asset_id_blinding_mask_x_amount_sum += se.real_out_asset_id_blinding_mask * se.amount;                                        // += r_i * a_i
	addRefScalar(&ogc.RealInAssetIdBlindingMaskXAmountSum, new(edwards25519.Scalar).Multiply(src.RealOutAssetIdBlindingMask.Scalar, zanocrypto.ScalarInt(src.Amount)))
	//ogc.pseudo_outs_blinded_asset_ids.emplace_back(pseudo_out_blinded_asset_id);
	ogc.PseudoOutsBlindedAssetIds = append(ogc.PseudoOutsBlindedAssetIds, &zanobase.Point{pseudoOutBlindedAssetId})
	//ogc.pseudo_outs_plus_real_out_blinding_masks.emplace_back(pseudo_out_asset_id_blinding_mask + se.real_out_asset_id_blinding_mask);
	ogc.PseudoOutsPlusRealOutBlindingMasks = append(ogc.PseudoOutsPlusRealOutBlindingMasks, src.RealOutAssetIdBlindingMask)

	//crypto::point_t pseudo_out_amount_commitment = se.amount * source_blinded_asset_id + pseudo_out_amount_blinding_mask * crypto::c_point_G; // A^p_i = a_i * T_i + f'_i * G
	pseudoOutAmountCommitment := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(zanocrypto.ScalarInt(src.Amount), sourceBlindedAssetId, pseudoOutAmountBlindingMask)
	//sig.pseudo_out_amount_commitment = (crypto::c_scalar_1div8 * pseudo_out_amount_commitment).to_public_key();
	sig.PseudoOutAmountCommitment = &zanobase.Point{new(edwards25519.Point).ScalarMult(zanocrypto.Sc1div8, pseudoOutAmountCommitment)}
	//ogc.pseudo_out_amount_commitments_sum += pseudo_out_amount_commitment;
	addRefPoint(&ogc.PseudoOutAmountCommitmentsSum, pseudoOutAmountCommitment)

	// = three-layers ring signature data outline =
	// (j in [0, ring_size-1])
	// layer 0 ring
	//     se.outputs[j].stealth_address;
	// layer 0 secret (with respect to G)
	//     in_contexts[i].in_ephemeral.sec;
	// layer 0 linkability
	//     in.k_image;
	//
	// layer 1 ring
	//     crypto::point_t(se.outputs[j].amount_commitment) - pseudo_out_amount_commitment;
	// layer 1 secret (with respect to G)
	//     se.real_out_amount_blinding_mask - pseudo_out_amount_blinding_mask;
	//
	// layer 2 ring
	//     crypto::point_t(se.outputs[j].blinded_asset_id) - pseudo_out_asset_id;
	// layer 2 secret (with respect to X)
	//     -pseudo_out_asset_id_blinding_mask;

	//sig := new(zanobase.ZCSig)
	ring := make([]zanocrypto.CLSAG_GGXInputRef, len(src.Outputs))

	for n := range ring {
		ring[n].StealthAddress = src.Outputs[n].StealthAddress.Point
		ring[n].AmountCommitment = src.Outputs[n].AmountCommitment.Point
		ring[n].BlindedAssetID = src.Outputs[n].BlindedAssetID.Point
	}

	//sig, err := zanocrypto.GenerateCLSAG_GGX(txHashForSig,
	//crypto::generate_CLSAG_GGX(tx_hash_for_signature, ring, pseudo_out_amount_commitment, pseudo_out_blinded_asset_id, in.k_image, in_context.in_ephemeral.sec,
	//se.real_out_amount_blinding_mask - pseudo_out_amount_blinding_mask,
	//-pseudo_out_asset_id_blinding_mask, in_context.real_out_index, sig.clsags_ggx);

	return nil
}
