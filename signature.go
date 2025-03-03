package zanolib

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/ModChain/edwards25519"
)

type ZCSig struct {
	// ZC_sig
	PseudoOutAmountCommitment Value256 // premultiplied by 1/8
	PseudoOutBlindedAssetId   Value256 // premultiplied by 1/8
	// crypto::CLSAG_GGX_signature_serialized clsags_ggx
	GGX *CLSAG_Sig
}

type CLSAG_Sig struct {
	C   Value256   // scalar_t
	R_G []Value256 // for G-components (layers 0, 1),    size = size of the ring
	R_X []Value256 // for X-component  (layer 2),        size = size of the ring
	K1  Value256   // public_key auxiliary key image for layer 1 (G)
	K2  Value256   // public_key auxiliary key image for layer 2 (X)
}

func (w *Wallet) Sign(ftp *FinalizeTxParam) (*FinalizedTx, error) {
	if !bytes.Equal(ftp.SpendPubKey[:], w.SpendPubKey.Serialize()) {
		return nil, errors.New("spend key does not match")
	}

	if ftp.TxVersion != 2 {
		return nil, fmt.Errorf("unsupported tx version = %d", ftp.TxVersion)
	}
	tx := &Transaction{Version: 2}
	res := &FinalizedTx{
		Tx:  tx,
		FTP: ftp,
	}

	// generate_key_image_helper(sender_account_keys, src_entr.real_out_tx_key, src_entr.real_output_in_tx_index, in_context.in_ephemeral, img)
	// → derive_ephemeral_key_helper(ack, tx_public_key, real_output_index, in_ephemeral)
	// → crypto::generate_key_image(in_ephemeral.pub, in_ephemeral.sec, ki);

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
	var pubKey Value256
	copy(pubKey[:], pub.Serialize())
	tx.Extra = append(tx.Extra, &Payload{Tag: 22, Value: pubKey})
	tx.Extra = append(tx.Extra, &Payload{Tag: 23, Value: uint16(0)})

	// use ftp.Sources
	for _, src := range ftp.Sources {
		vin := &TxInZcInput{}
		var prev uint64
		for _, out := range src.Outputs {
			val := payloadAs[uint64](out.OutReference)
			cur := val - prev
			prev = val
			vin.KeyOffsets = append(vin.KeyOffsets, payloadFor(cur))
		}
		tx.Vin = append(tx.Vin, payloadFor(vin))
	}

	return res, nil
}
