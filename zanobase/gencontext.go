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

func (g *GenContext) Resize(inCnt, outCnt int) {
	g.AssetIds = resizeSlice(g.AssetIds, outCnt)
	g.BlindedAssetIds = resizeSlice(g.BlindedAssetIds, outCnt)
	g.AmountCommitments = resizeSlice(g.AmountCommitments, outCnt)
	g.AssetIdBlindingMasks = resizeSlice(g.AssetIdBlindingMasks, outCnt)
	g.Amounts = resizeSlice(g.Amounts, outCnt)
	g.AmountBlindingMasks = resizeSlice(g.AmountBlindingMasks, outCnt)
	g.ZcInputAmounts = resizeSlice(g.ZcInputAmounts, inCnt)
}

func resizeSlice[S ~[]E, E any](s S, n int) S {
	if len(s) >= n {
		return s[:n]
	}
	// According to source for slices.Grow, this expression allocates only once
	return append(s, make([]E, n-len(s))...)
}

type KeyPair struct {
	// TODO KeyPair doesn't have a BEGIN_SERIALIZE_OBJECT
	Pub *Point
	Sec *Scalar
}
