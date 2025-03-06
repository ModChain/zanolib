package zanobase

type GenContext struct {
	AssetIds                            []*Point
	BlindedAssetIds                     []*Point
	AmountCommitments                   []*Point
	AssetIdBlindingMasks                []*Scalar
	Amounts                             []*Scalar
	AmountBlindingMasks                 []*Scalar
	PseudoOutsBlindedAssetIds           []*Point
	PseudoOutsPlusRealOutBlindingMasks  []*Scalar
	RealZcInsAssetIds                   []*Point
	ZcInputAmounts                      []uint64
	PseudoOutAmountCommitmentsSum       *Point
	PseudoOutAmountBlindingMasksSum     *Scalar
	RealInAssetIdBlindingMaskXAmountSum *Scalar
	AmountCommitmentsSum                *Point
	AmountBlindingMasksSum              *Scalar
	AssetIdBlindingMaskXAmountSum       *Scalar
	AoAssetId                           *Point
	AoAssetIdPt                         *Point
	AoAmountCommitment                  *Point
	AoAmountBlindingMask                *Scalar
	AoCommitmentInOutputs               bool
	TxKey                               *KeyPair
	TxPubKeyP                           *Point
}

type KeyPair struct {
	// TODO KeyPair doesn't have a BEGIN_SERIALIZE_OBJECT
	Pub *Point
	Sec *Scalar
}
