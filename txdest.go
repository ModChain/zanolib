package zanolib

import (
	"encoding/binary"
	"slices"

	"github.com/ModChain/edwards25519"
	"github.com/ModChain/zanolib/zanobase"
	"github.com/ModChain/zanolib/zanocrypto"
)

type TxDestHtlcOut struct {
	Expiration uint64
	HtlcHash   zanobase.Value256 // crypto::hash
}

type TxDest struct {
	Amount          uint64
	Addr            []*zanobase.AccountPublicAddr      // account_public_address; destination address, in case of 1 address - txout_to_key, in case of more - txout_multisig
	MinimumSigs     uint64                             // if txout_multisig: minimum signatures that are required to spend this output (minimum_sigs <= addr.size())  IF txout_to_key - not used
	AmountToProvide uint64                             // amount money that provided by initial creator of tx, used with partially created transactions
	UnlockTime      uint64                             //
	HtlcOptions     *TxDestHtlcOut                     // destination_option_htlc_out
	AssetId         zanobase.Value256                  // not blinded, not premultiplied
	Flags           uint64                             // set of flags (see tx_destination_entry_flags)
	blindedAssetId  *edwards25519.ExtendedGroupElement // intermediate value, used internally
}

func (dst *TxDest) StealthAddress(scalar *[32]byte) *zanobase.Value256 {
	// 1. Compute H = h * G
	var H edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&H, scalar)

	var P edwards25519.ExtendedGroupElement
	ok := P.FromBytes(dst.Addr[0].SpendKey.PB32())
	if !ok {
		panic("invalid public key for recipient")
	}

	// 3. Add the two points: R = H + P
	var cachedP edwards25519.CachedGroupElement
	P.ToCached(&cachedP)

	var R edwards25519.CompletedGroupElement
	edwards25519.GeAdd(&R, &H, &cachedP)

	// 4. Convert R to an ExtendedGroupElement
	var RExtended edwards25519.ExtendedGroupElement
	R.ToExtended(&RExtended)
	// 5. Convert back to a 32-byte compressed public key
	var stealthAddress zanobase.Value256
	RExtended.ToBytes(stealthAddress.PB32())
	return &stealthAddress
}

func (dst *TxDest) ConcealingPoint(scalar *[32]byte) *zanobase.Value256 {
	// ConcealingPoint
	var concealingPoint zanobase.Value256
	concealingPoint = zanocrypto.HashToScalar(slices.Concat([]byte("ZANO_HDS_OUT_CONCEALING_POINT__\x00"), scalar[:]))

	var V edwards25519.ExtendedGroupElement
	if !V.FromBytes(dst.Addr[0].ViewKey.PB32()) {
		panic("invalid view key for recipient")
	}
	// multiply
	var Qproj edwards25519.ProjectiveGroupElement
	var ZeroSc [32]byte
	edwards25519.GeDoubleScalarMultVartime(
		&Qproj,
		concealingPoint.PB32(),
		&V,
		&ZeroSc, // b=0
	)
	Qproj.ToBytes(concealingPoint.PB32())

	return &concealingPoint
}

func (dst *TxDest) BlindedAssetId(scalar *[32]byte) *zanobase.Value256 {
	// zanocrypto.HashToScalar will also reduce
	assetBlindingMask := zanocrypto.HashToScalar(slices.Concat([]byte("ZANO_HDS_OUT_ASSET_BLIND_MASK__\x00"), scalar[:]))

	// 1) Decompress dst.AssetId (Q) to an ExtendedGroupElement
	var Q edwards25519.ExtendedGroupElement
	if !Q.FromBytes(dst.AssetId.PB32()) {
		panic("invalid compressed asset_id point")
	}

	// 3) Multiply R = assetBlindingMask * X
	var Rproj edwards25519.ProjectiveGroupElement
	edwards25519.GeDoubleScalarMultVartime(
		&Rproj,
		&assetBlindingMask,
		zanocrypto.C_point_X,
		&zanocrypto.ScZero, // second scalar = 0
	)

	// Convert Rproj -> Extended
	var Rext edwards25519.ExtendedGroupElement
	{
		var tmp [32]byte
		Rproj.ToBytes(&tmp)
		if !Rext.FromBytes(&tmp) {
			panic("unexpected R decomposition error")
		}
	}

	// 4) S = Q + R
	var Qcached edwards25519.CachedGroupElement
	Q.ToCached(&Qcached)

	var Scomp edwards25519.CompletedGroupElement
	edwards25519.GeAdd(&Scomp, &Rext, &Qcached)

	var Sext edwards25519.ExtendedGroupElement
	Scomp.ToExtended(&Sext)

	dst.blindedAssetId = &Sext // store before multiplication by 1/8

	// 1) Convert S to Projective
	var Sproj edwards25519.ProjectiveGroupElement
	Sext.ToProjective(&Sproj)

	// 2) Multiply by (1/8)
	var Tproj edwards25519.ProjectiveGroupElement
	edwards25519.GeDoubleScalarMultVartime(
		&Tproj,
		&zanocrypto.Sc1div8,
		&Sext,
		&zanocrypto.ScZero, // zero
	)

	// 3) Convert Tproj -> Extended
	var Text edwards25519.ExtendedGroupElement
	Tproj.ToExtended(&Text)

	// 4) Finally compress to bytes
	var blindedAssetId zanobase.Value256
	Text.ToBytes(blindedAssetId.PB32())

	return &blindedAssetId
}

func (dst *TxDest) AmountCommitment(scalar *[32]byte) *zanobase.Value256 {
	// amount_blinding_mask = crypto::hash_helper_t::hs(CRYPTO_HDS_OUT_AMOUNT_BLINDING_MASK, h)
	amountBlindingMask := zanocrypto.HashToScalar(
		slices.Concat([]byte("ZANO_HDS_OUT_AMOUNT_BLIND_MASK_\x00"), scalar[:]),
	)
	// 2) Convert dst.Amount (uint64) to a 32-byte scalar
	var amountScalar [32]byte
	binary.LittleEndian.PutUint64(amountScalar[:], dst.Amount)
	edwards25519.ScReduce32(&amountScalar, &amountScalar)

	// 3) Let T = dst.BlindedAssetId(scalar).ToExtended()
	//    (assuming BlindedAssetId(...) returns something we can turn into an ExtendedGroupElement)
	TExt := dst.blindedAssetId
	//dst.BlindedAssetId(scalar).ToExtended()

	// 4) We want R = (amount)*T + (mask)*c_point_G
	//    But GeDoubleScalarMultVartime(&RProj, a, A, b) => a*A + b*B always uses B=basepoint.
	//    So instead do:
	//        P = (amount)*T
	//        Q = (mask)*c_point_G
	//        R = P + Q

	// --- P = amount*T ---
	var PProj edwards25519.ProjectiveGroupElement
	edwards25519.GeDoubleScalarMultVartime(&PProj, &amountScalar, TExt, &zanocrypto.ScZero)

	// convert projective -> extended
	var PExt edwards25519.ExtendedGroupElement
	PProj.ToExtended(&PExt)

	// --- Q = mask*c_point_G ---
	//     c_point_G is presumably an *ExtendedGroupElement*
	var QProj edwards25519.ProjectiveGroupElement
	edwards25519.GeDoubleScalarMultVartime(&QProj, &amountBlindingMask, zanocrypto.C_point_G, &zanocrypto.ScZero)

	// convert projective -> extended
	var QExt edwards25519.ExtendedGroupElement
	QProj.ToExtended(&QExt)

	// --- R = P + Q ---
	var RCompleted edwards25519.CompletedGroupElement
	var PCached edwards25519.CachedGroupElement
	PExt.ToCached(&PCached)
	edwards25519.GeAdd(&RCompleted, &QExt, &PCached)

	// convert completed -> extended
	var RExt edwards25519.ExtendedGroupElement
	RCompleted.ToExtended(&RExt)

	// 5) Multiply R by (1/8):
	//    R2 = (1/8)*R = GeDoubleScalarMultVartime(r2, cScalar1div8, R, zero)
	var R2Proj edwards25519.ProjectiveGroupElement
	edwards25519.GeDoubleScalarMultVartime(&R2Proj, &zanocrypto.Sc1div8, &RExt, &zanocrypto.ScZero)

	// 6) Compress R2 => final 32 bytes
	var amountCommitment zanobase.Value256
	R2Proj.ToBytes(amountCommitment.PB32())

	return &amountCommitment
}
