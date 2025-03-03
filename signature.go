package zanolib

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/ModChain/edwards25519"
	"github.com/ModChain/zanolib/zanobase"
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
		tx.Vin = append(tx.Vin, zanobase.VariantFor(vin))
	}

	return res, nil
}
