package zanolib

type TxOutZarcanium struct {
	// tx_out_zarcanum
	StealthAddress   [32]byte
	ConcealingPoint  [32]byte // group element Q, see also Zarcanum paper, premultiplied by 1/8
	AmountCommitment [32]byte // premultiplied by 1/8
	BlindedAssetId   [32]byte // group element T, premultiplied by 1/8
	EncryptedAmount  uint64
	MixAttr          uint8
}
