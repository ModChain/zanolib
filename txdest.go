package zanolib

import (
	"encoding/binary"
	"io"
)

type TxDestHtlcOut struct {
	Expiration uint64
	HtlcHash   [32]byte // crypto::hash
}

type TxDest struct {
	Amount          uint64
	Addr            []*AccountPublicAddr // account_public_address; destination address, in case of 1 address - txout_to_key, in case of more - txout_multisig
	MinimumSigs     uint64               // if txout_multisig: minimum signatures that are required to spend this output (minimum_sigs <= addr.size())  IF txout_to_key - not used
	AmountToProvide uint64               // amount money that provided by initial creator of tx, used with partially created transactions
	UnlockTime      uint64               //
	HtlcOptions     *TxDestHtlcOut       // destination_option_htlc_out
	AssetId         [32]byte             // not blinded, not premultiplied
	Flags           uint64               // set of flags (see tx_destination_entry_flags)
}

func (dst *TxDest) ReadFrom(r io.Reader) (int64, error) {
	rc := rc(r)
	err := binary.Read(rc, binary.LittleEndian, &dst.Amount)
	if err != nil {
		return rc.error(err)
	}
	addrCount, err := VarintReadUint64(rc)
	if err != nil {
		return rc.error(err)
	}
	dst.Addr = make([]*AccountPublicAddr, addrCount)
	for n := range dst.Addr {
		addr := new(AccountPublicAddr)
		_, err = addr.ReadFrom(rc)
		if err != nil {
			return rc.error(err)
		}
		dst.Addr[n] = addr
	}
	err = binary.Read(rc, binary.LittleEndian, &dst.MinimumSigs)
	if err != nil {
		return rc.error(err)
	}
	err = binary.Read(rc, binary.LittleEndian, &dst.AmountToProvide)
	if err != nil {
		return rc.error(err)
	}
	err = binary.Read(rc, binary.LittleEndian, &dst.UnlockTime)
	if err != nil {
		return rc.error(err)
	}
	dst.HtlcOptions = new(TxDestHtlcOut)
	err = binary.Read(rc, binary.LittleEndian, &dst.HtlcOptions.Expiration)
	if err != nil {
		return rc.error(err)
	}
	_, err = io.ReadFull(rc, dst.HtlcOptions.HtlcHash[:])
	if err != nil {
		return rc.error(err)
	}
	_, err = io.ReadFull(rc, dst.AssetId[:])
	if err != nil {
		return rc.error(err)
	}
	err = binary.Read(rc, binary.LittleEndian, &dst.Flags)
	if err != nil {
		return rc.error(err)
	}
	return rc.ret()
}
