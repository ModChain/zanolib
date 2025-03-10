package zanobase

import "golang.org/x/crypto/sha3"

type TransactionPrefix struct {
	Version Varint     `json:"version"` // varint, ==2
	Vin     []*Variant `json:"vin"`     // txin_v = boost::variant<txin_gen[0], txin_to_key[1], txin_multisig[2], txin_htlc[34], txin_zc_input[37]>
	Extra   []*Variant `json:"extra"`   // extra_v
	Vout    []*Variant `json:"vout"`    // tx_out_v = boost::variant<tx_out_bare[36], tx_out_zarcanum[38]>
}

type Transaction struct {
	Version Varint     `json:"version"` // varint, ==2
	Vin     []*Variant `json:"vin"`     // txin_v = boost::variant<txin_gen[0], txin_to_key[1], txin_multisig[2], txin_htlc[34], txin_zc_input[37]>
	Extra   []*Variant `json:"extra"`   // extra_v
	Vout    []*Variant `json:"vout"`    // tx_out_v = boost::variant<tx_out_bare[36], tx_out_zarcanum[38]>
	// up to here this was transaction_prefix
	Attachment []*Variant `json:"attachment,omitempty"`
	Signatures []*Variant `json:"signatures"` // signature_v = boost::variant<NLSAG_sig, void_sig, ZC_sig, zarcanum_sig>
	Proofs     []*Variant `json:"proofs"`     // proof_v
}

type TransactionV3 struct {
	Version Varint     `json:"version"` // varint, ==2
	Vin     []*Variant `json:"vin"`     // txin_v = boost::variant<txin_gen[0], txin_to_key[1], txin_multisig[2], txin_htlc[34], txin_zc_input[37]>
	Extra   []*Variant `json:"extra"`   // extra_v
	Vout    []*Variant `json:"vout"`    // tx_out_v = boost::variant<tx_out_bare[36], tx_out_zarcanum[38]>
	// up to here this was transaction_prefix
	Attachment []*Variant `json:"attachment,omitempty"`
	Signatures []*Variant `json:"signatures"`  // signature_v = boost::variant<NLSAG_sig, void_sig, ZC_sig, zarcanum_sig>
	Proofs     []*Variant `json:"proofs"`      // proof_v
	HardforkId uint8      `json:"hardfork_id"` // uint8_t
}

func (tx *Transaction) Prefix() *TransactionPrefix {
	return &TransactionPrefix{tx.Version, tx.Vin, tx.Extra, tx.Vout}
}

// Hash of a transaction prefix. Can fail if the variants contains invalid data
func (txp *TransactionPrefix) Hash() ([]byte, error) {
	h := sha3.NewLegacyKeccak256()
	err := Serialize(h, txp)
	return h.Sum(nil), err
}

func (tx *Transaction) GetFee() (uint64, bool) {
	// simple get fee: tx.Extra should contain a ZarcaniumTxDataV1
	for _, e := range tx.Extra {
		if e.Tag == TagZarcaniumTxDataV1 {
			return e.Value.(*ZarcaniumTxDataV1).Fee, true
		}
	}
	return 0, false
}
