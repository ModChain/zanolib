package zanobase

type TxSourceOutputEntry struct {
	OutReference     *Payload // TxOutRef // either global output index or ref_by_id
	StealthAddress   Value256 // crypto::public_key, a.k.a output's one-time public key
	ConcealingPoint  Value256 // only for ZC outputs
	AmountCommitment Value256 // only for ZC outputs
	BlindedAssetID   Value256 // only for ZC outputs
}

type TxSource struct {
	Outputs                    []*TxSourceOutputEntry
	RealOutput                 uint64
	RealOutTxKey               Value256 // crypto::public_key
	RealOutAmountBlindingMask  Value256 // crypto::scalar_t
	RealOutAssetIdBlindingMask Value256 // crypto::scalar_t
	RealOutInTxIndex           uint64   // size_t, index in transaction outputs vector
	Amount                     uint64
	TransferIndex              uint64
	MultisigId                 Value256 // crypto::hash if txin_multisig: multisig output id
	MsSigsCount                uint64   // size_t
	MsKeysCount                uint64   // size_t
	SeparatelySignedTxComplete bool
	HtlcOrigin                 string // for htlc, specify origin. len = 1, content = "\x00" ?
}
