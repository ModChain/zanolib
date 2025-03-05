package zanolib

import "github.com/ModChain/zanolib/zanobase"

type TxSourceOutputEntry struct {
	OutReference     *zanobase.Variant // TxOutRef // either global output index or ref_by_id
	StealthAddress   zanobase.Value256 // crypto::public_key, a.k.a output's one-time public key
	ConcealingPoint  zanobase.Value256 // only for ZC outputs
	AmountCommitment zanobase.Value256 // only for ZC outputs
	BlindedAssetID   zanobase.Value256 // only for ZC outputs
}

type TxSource struct {
	Outputs                    []*TxSourceOutputEntry
	RealOutput                 uint64
	RealOutTxKey               zanobase.Value256 // crypto::public_key
	RealOutAmountBlindingMask  zanobase.Value256 // crypto::scalar_t
	RealOutAssetIdBlindingMask zanobase.Value256 // crypto::scalar_t
	RealOutInTxIndex           uint64            // size_t, index in transaction outputs vector
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
	return !src.RealOutAssetIdBlindingMask.IsZero()
}

func (src *TxSource) generateZCSig() *zanobase.ZCSig {
	//sig := new(zanobase.ZCSig)
	return nil
}
