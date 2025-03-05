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
	Addr            []*zanobase.AccountPublicAddr // account_public_address; destination address, in case of 1 address - txout_to_key, in case of more - txout_multisig
	MinimumSigs     uint64                        // if txout_multisig: minimum signatures that are required to spend this output (minimum_sigs <= addr.size())  IF txout_to_key - not used
	AmountToProvide uint64                        // amount money that provided by initial creator of tx, used with partially created transactions
	UnlockTime      uint64                        //
	HtlcOptions     *TxDestHtlcOut                // destination_option_htlc_out
	AssetId         zanobase.Value256             // not blinded, not premultiplied
	Flags           uint64                        // set of flags (see tx_destination_entry_flags)
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
	projectiveToExtended(&Tproj, &Text)

	// 4) Finally compress to bytes
	var blindedAssetId zanobase.Value256
	Text.ToBytes(blindedAssetId.PB32())

	return &blindedAssetId
}

func (dst *TxDest) AmountCommitment(scalar *[32]byte) *zanobase.Value256 {
	amountBlindingMask := zanocrypto.HashToScalar(slices.Concat([]byte("ZANO_HDS_OUT_AMOUNT_BLIND_MASK_\x00"), scalar[:]))
	// amount_commitment = de.amount * blinded_asset_id + amount_blinding_mask * crypto::c_point_G;
	// out.amount_commitment = (crypto::c_scalar_1div8 * amount_commitment).to_public_key(); // E = 1/8 * e * T + 1/8 * y * G

	var amountScalar [32]byte
	binary.LittleEndian.PutUint64(amountScalar[:], dst.Amount)

	// 3) Compute: R = amount*T + amountBlindingMask*Basepoint
	//    GeDoubleScalarMultVartime(r, a, A, b) => r = a*A + b*B
	var RProj edwards25519.ProjectiveGroupElement
	edwards25519.GeDoubleScalarMultVartime(&RProj, &amountScalar, dst.BlindedAssetId(scalar).ToExtended(), &amountBlindingMask)

	// 4) Convert Projective -> Extended
	var RExt edwards25519.ExtendedGroupElement
	//RProj.ToExtended(&RExt)
	projectiveToExtended(&RProj, &RExt)

	// 5) Multiply by 1/8: R2 = (1/8)*RExt
	//    We do this via GeDoubleScalarMultVartime(r2, c, R, zero) => c*R + 0*Basepoint
	var R2Proj edwards25519.ProjectiveGroupElement
	edwards25519.GeDoubleScalarMultVartime(&R2Proj, &zanocrypto.Sc1div8, &RExt, &zanocrypto.ScZero)

	// 6) Finally, convert R2 to bytes (the compressed "public key")
	var amountCommitment zanobase.Value256
	R2Proj.ToBytes(amountCommitment.PB32())

	return &amountCommitment
}
