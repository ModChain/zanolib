package zanolib

import "io"

type Transaction struct {
	Version uint64     // varint, ==2
	Vin     []*Payload // txin_v = boost::variant<txin_gen[0], txin_to_key[1], txin_multisig[2], txin_htlc[34], txin_zc_input[37]>
	Extra   []*Payload // extra_v
	Vout    []*Payload // tx_out_v = boost::variant<tx_out_bare[36], tx_out_zarcanum[38]>
	// up to here this was transaction_prefix
	Attachment []*Payload
	Signatures []*Payload // signature_v = boost::variant<NLSAG_sig, void_sig, ZC_sig, zarcanum_sig>
	Proofs     []*Payload // proof_v
}

func (tx *Transaction) ReadFrom(r io.Reader) (int64, error) {
	rc := rc(r)
	var err error
	tx.Version, err = VarintReadUint64(rc)
	if err != nil {
		return rc.error(err)
	}
	return rc.magic(&tx.Vin, &tx.Extra, &tx.Vout, &tx.Attachment, &tx.Signatures, &tx.Proofs)
}
