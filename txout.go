package zanolib

import (
	"encoding/binary"
	"io"
)

type TxOutZarcanium struct {
	// tx_out_zarcanum
	StealthAddress   [32]byte
	ConcealingPoint  [32]byte // group element Q, see also Zarcanum paper, premultiplied by 1/8
	AmountCommitment [32]byte // premultiplied by 1/8
	BlindedAssetId   [32]byte // group element T, premultiplied by 1/8
	EncryptedAmount  uint64
	MixAttr          uint8
}

func (txout *TxOutZarcanium) ReadFrom(r io.Reader) (int64, error) {
	rc := rc(r)
	err := rc.readFull(txout.StealthAddress[:])
	if err != nil {
		return rc.error(err)
	}
	err = rc.readFull(txout.ConcealingPoint[:])
	if err != nil {
		return rc.error(err)
	}
	err = rc.readFull(txout.AmountCommitment[:])
	if err != nil {
		return rc.error(err)
	}
	err = rc.readFull(txout.BlindedAssetId[:])
	if err != nil {
		return rc.error(err)
	}
	err = binary.Read(rc, binary.LittleEndian, &txout.EncryptedAmount)
	if err != nil {
		return rc.error(err)
	}
	err = binary.Read(rc, binary.LittleEndian, &txout.MixAttr)
	if err != nil {
		return rc.error(err)
	}
	return rc.ret()
}
