package zanolib

type TxSourceOutputEntry struct {
	OutReference     *Payload // TxOutRef // either global output index or ref_by_id
	StealthAddress   [32]byte // crypto::public_key, a.k.a output's one-time public key
	ConcealingPoint  [32]byte // only for ZC outputs
	AmountCommitment [32]byte // only for ZC outputs
	BlindedAssetID   [32]byte // only for ZC outputs
}

type TxSource struct {
	Outputs                    []*TxSourceOutputEntry
	RealOutput                 uint64
	RealOutTxKey               [32]byte // crypto::public_key
	RealOutAmountBlindingMask  [32]byte // crypto::scalar_t
	RealOutAssetIdBlindingMask [32]byte // crypto::scalar_t
	RealOutInTxIndex           uint64   // size_t, index in transaction outputs vector
	Amount                     uint64
	TransferIndex              uint64
	MultisigId                 [32]byte // crypto::hash if txin_multisig: multisig output id
	MsSigsCount                uint64   // size_t
	MsKeysCount                uint64   // size_t
	SeparatelySignedTxComplete bool
	HtlcOrigin                 string // for htlc, specify origin. len = 1, content = "\x00" ?
}
