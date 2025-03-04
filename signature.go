package zanolib

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/ModChain/edwards25519"
	"github.com/ModChain/zanolib/zanobase"
	"github.com/ModChain/zanolib/zanocrypto"
)

func (w *Wallet) Sign(ftp *FinalizeTxParam, oneTimeKey []byte) (*FinalizedTx, error) {
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

	// construct tx uses some method to get an intial value?
	if oneTimeKey == nil {
		var err error
		priv, err := edwards25519.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
		oneTimeKey = priv.Serialize()
		slices.Reverse(oneTimeKey)
	}
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
			// → derive_ephemeral_key_helper(ack, tx_public_key, real_output_index, in_ephemeral)
			//   → crypto::generate_key_derivation(tx_public_key, ack.view_secret_key, recv_derivation)
			// → crypto::generate_key_image(in_ephemeral.pub, in_ephemeral.sec, ki)
			val := zanobase.VariantAs[uint64](out.OutReference)
			cur := val - prev
			prev = val
			vin.KeyOffsets = append(vin.KeyOffsets, zanobase.VariantFor(cur))
		}

		// Derive ephemeral
		var realOutTxKey [32]byte
		copy(realOutTxKey[:], src.RealOutTxKey[:])

		// generate_key_image_helper(sender_account_keys, src_entr.real_out_tx_key,
		var ackViewSecretKey [32]byte
		copy(ackViewSecretKey[:], w.ViewPrivKey.Serialize())
		slices.Reverse(ackViewSecretKey[:])
		derivation, err := zanocrypto.GenerateKeyDerivation(realOutTxKey, ackViewSecretKey)
		if err != nil {
			return nil, err
		}
		var ackSpendPublic [32]byte
		copy(ackSpendPublic[:], w.SpendPubKey.Serialize())
		in_e_pub, err := zanocrypto.DerivePublicKey(derivation, src.RealOutInTxIndex, &ackSpendPublic)
		if err != nil {
			return nil, err
		}
		var ackSpendPriv [32]byte
		copy(ackSpendPriv[:], w.SpendPrivKey.Serialize())
		slices.Reverse(ackSpendPriv[:])
		in_e_sec, err := zanocrypto.DeriveSecretKey(derivation, src.RealOutInTxIndex, &ackSpendPriv)
		if err != nil {
			return nil, err
		}
		// in_context.in_ephemeral.pub == in_context.outputs[in_context.real_out_index].stealth_address
		if !bytes.Equal(in_e_pub[:], src.Outputs[src.RealOutput].StealthAddress[:]) {
			return nil, errors.New("derived public key missmatch with output public key!")
		}
		// key image
		//slices.Reverse(in_e_sec[:])
		keyImage, err := zanocrypto.ComputeKeyImage(in_e_sec, in_e_pub)
		if err != nil {
			return nil, err
		}
		vin.KeyImage = keyImage
		//realOut := src.Outputs[src.RealOutput]
		//RealOutTxKey               Value256 // crypto::public_key
		//RealOutAmountBlindingMask  Value256 // crypto::scalar_t
		//RealOutAssetIdBlindingMask Value256 // crypto::scalar_t
		//RealOutInTxIndex           uint64   // size_t, index in transaction outputs vector
		tx.Vin = append(tx.Vin, zanobase.VariantFor(vin))
	}

	// prepared outs
	for _, dst := range ftp.PreparedDestinations {
		vout := &zanobase.TxOutZarcanium{
			BlindedAssetId:  dst.AssetId,
			EncryptedAmount: dst.Amount, // FIXME
		}

		tx.Vout = append(tx.Vout, zanobase.VariantFor(vout))
	}

	return res, nil
}
