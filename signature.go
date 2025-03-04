package zanolib

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/ModChain/edwards25519"
	"github.com/ModChain/zanolib/zanobase"
	"github.com/ModChain/zanolib/zanocrypto"
)

func (w *Wallet) Sign(ftp *FinalizeTxParam) (*FinalizedTx, error) {
	if !bytes.Equal(ftp.SpendPubKey[:], w.SpendPubKey.Serialize()) {
		return nil, errors.New("spend key does not match")
	}

	if ftp.TxVersion != 2 {
		return nil, fmt.Errorf("unsupported tx version = %d", ftp.TxVersion)
	}
	tx := &zanobase.Transaction{Version: 2}
	res := &FinalizedTx{
		Tx:  tx,
		FTP: ftp,
	}

	// void wallet2::sign_transfer(const std::string& tx_sources_blob, std::string& signed_tx_blob, currency::transaction& tx)
	// @ src/wallet/wallet2.cpp 4299

	// finalize_transaction(ft.ftp, ft.tx, ft.one_time_key, false);
	// @ src/wallet/wallet2.cpp 7954

	// currency::construct_tx(m_account.get_keys(), ftp, result);
	// @ src/currency_core/currency_format_utils.cpp 2372

	// FIXME one time key hardcoded
	// construct tx uses some method to get an intial value?
	oneTimeKey := must(hex.DecodeString("955f1e1fc3262ba2f307b64e60a960e18ff1072300dbf297114739fabb000204"))
	copy(res.OneTimeKey[:], oneTimeKey)
	slices.Reverse(oneTimeKey)
	priv, pub, err := edwards25519.PrivKeyFromScalar(oneTimeKey)
	if err != nil {
		return nil, err
	}
	_, _ = priv, pub

	var pubKey zanobase.Value256
	copy(pubKey[:], pub.Serialize())
	tx.Extra = append(tx.Extra, &zanobase.Variant{Tag: zanobase.TagPubKey, Value: pubKey})
	tx.Extra = append(tx.Extra, &zanobase.Variant{Tag: zanobase.TagEtcTxFlags16, Value: uint16(0)}) // Flags

	// use ftp.Sources
	for _, src := range ftp.Sources {
		vin := &zanobase.TxInZcInput{}
		var prev uint64
		for _, out := range src.Outputs {
			// generate_key_image_helper(sender_account_keys, src_entr.real_out_tx_key, src_entr.real_output_in_tx_index, in_context.in_ephemeral, img))
			val := zanobase.VariantAs[uint64](out.OutReference)
			cur := val - prev
			prev = val
			vin.KeyOffsets = append(vin.KeyOffsets, zanobase.VariantFor(cur))
		}
		//realOut := src.Outputs[src.RealOutput]
		//RealOutTxKey               Value256 // crypto::public_key
		//RealOutAmountBlindingMask  Value256 // crypto::scalar_t
		//RealOutAssetIdBlindingMask Value256 // crypto::scalar_t
		//RealOutInTxIndex           uint64   // size_t, index in transaction outputs vector
		tx.Vin = append(tx.Vin, zanobase.VariantFor(vin))
	}

	return res, nil
}

// Returns ephemeralSec [32]byte, ephemeralPub [32]byte, keyImage [32]byte, error
func ephemeralDerive(
	spendPrivBytes [32]byte,
	realOutTxKey [32]byte,
	realOutInTxIndex uint64,
) ([32]byte, [32]byte, [32]byte, error) {

	var ephemeralSec [32]byte
	var ephemeralPub [32]byte
	var keyImage [32]byte

	// 1) Parse our main private spend key into an edwards25519 scalar (32 bytes).
	//    Typically, we can just keep it as-is. But we often want it reduced mod l.
	//    This library's "ScReduce" can ensure it is in range.
	edwards25519.ScReduce32(&spendPrivBytes, &spendPrivBytes) // in-place is okay

	// 2) Parse realOutTxKey into an ExtendedGroupElement
	p := new(edwards25519.ExtendedGroupElement)
	ok := p.FromBytes(&realOutTxKey)
	if !ok {
		return ephemeralSec, ephemeralPub, keyImage, fmt.Errorf("invalid realOutTxKey: cannot decode extended group element")
	}

	// 3) ephemeralPoint = realOutTxKey * spendPriv
	//    We can do that by using GeDoubleScalarMultVartime(...) with b=0
	//    => ephemeralPoint = a*A + b*B = spendPriv * p + 0 * B
	var ephemeralPoint edwards25519.ProjectiveGroupElement
	var zero [32]byte // b=0
	edwards25519.GeDoubleScalarMultVartime(&ephemeralPoint, &spendPrivBytes, p, &zero)

	// Convert ephemeralPoint (ProjectiveGroupElement) to bytes
	var ephemeralPointBytes [32]byte
	ephemeralPoint.ToBytes(&ephemeralPointBytes)

	// 4) ephemeralSec = HashToScalar( ephemeralPointBytes || realOutInTxIndex )
	//    We'll define hashToScalar below
	ephemeralSec = zanocrypto.HashToScalar(ephemeralPointBytes[:]) // FIXME append(ephemeralPointBytes[:], realOutInTxIndex))

	// 5) ephemeralPub = ephemeralSec * G
	//    G is the base point. We can do:
	var ephemeralPubPoint edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&ephemeralPubPoint, &ephemeralSec)
	ephemeralPubPoint.ToBytes(&ephemeralPub)
	ephemeralPubObj, err := edwards25519.ParsePubKey(ephemeralPub[:])
	if err != nil {
		return ephemeralSec, ephemeralPub, keyImage, err
	}

	// 6) keyImage = ephemeralSec * Hp(ephemeralPub)
	//    We need hashToPoint(ephemeralPub), which returns an ExtendedGroupElement
	HpPoint, err := zanocrypto.HashToEC(ephemeralPubObj)
	if err != nil {
		return ephemeralSec, ephemeralPub, keyImage, err
	}

	// Multiply ephemeralSec * HpPoint => keyImage
	// We can do that with "GeDoubleScalarMultVartime" again, or a simpler path:
	var keyImageProjective edwards25519.ProjectiveGroupElement
	edwards25519.GeDoubleScalarMultVartime(&keyImageProjective, &ephemeralSec, HpPoint, &zero)

	keyImageProjective.ToBytes(&keyImage)

	return ephemeralSec, ephemeralPub, keyImage, nil
}
