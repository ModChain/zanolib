package zanobase

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

func (tx *Transaction) Prefix() *TransactionPrefix {
	return &TransactionPrefix{tx.Version, tx.Vin, tx.Extra, tx.Vout}
}
