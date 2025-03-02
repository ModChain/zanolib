package zanolib

import (
	"encoding/binary"
	"io"
)

type RefById struct {
	Hash [32]byte // source transaction hash
	N    uint32   // output index in source transaction
}

func (ref *RefById) ReadFrom(r io.Reader) (int64, error) {
	rc := rc(r)
	_, err := io.ReadFull(rc, ref.Hash[:])
	if err != nil {
		return rc.error(err)
	}
	err = binary.Read(rc, binary.LittleEndian, &ref.N)
	if err != nil {
		return rc.error(err)
	}
	return rc.ret()
}
