package zanolib

type TxDestHtlcOut struct {
	Expiration uint64
	HtlcHash   Value256 // crypto::hash
}

type TxDest struct {
	Amount          uint64
	Addr            []*AccountPublicAddr // account_public_address; destination address, in case of 1 address - txout_to_key, in case of more - txout_multisig
	MinimumSigs     uint64               // if txout_multisig: minimum signatures that are required to spend this output (minimum_sigs <= addr.size())  IF txout_to_key - not used
	AmountToProvide uint64               // amount money that provided by initial creator of tx, used with partially created transactions
	UnlockTime      uint64               //
	HtlcOptions     *TxDestHtlcOut       // destination_option_htlc_out
	AssetId         Value256             // not blinded, not premultiplied
	Flags           uint64               // set of flags (see tx_destination_entry_flags)
}
